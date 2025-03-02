/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package awsoidc

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gorilla/websocket"
	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestOpenTunnelRequest(t *testing.T) {
	isBadParamErrFn := func(tt require.TestingT, err error, i ...any) {
		require.True(tt, trace.IsBadParameter(err), "expected bad parameter, got %v", err)
	}

	baseReqFn := func() OpenTunnelEC2Request {
		return OpenTunnelEC2Request{
			Region:          "us-east-1",
			InstanceID:      "i-123",
			VPCID:           "vpc-id",
			EC2SSHLoginUser: "ec2-user",
			EC2Address:      "127.0.0.1:22",
		}
	}

	for _, tt := range []struct {
		name            string
		req             func() OpenTunnelEC2Request
		errCheck        require.ErrorAssertionFunc
		reqWithDefaults OpenTunnelEC2Request
	}{
		{
			name: "no fields",
			req: func() OpenTunnelEC2Request {
				return OpenTunnelEC2Request{}
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing region",
			req: func() OpenTunnelEC2Request {
				r := baseReqFn()
				r.Region = ""
				return r
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing instance id",
			req: func() OpenTunnelEC2Request {
				r := baseReqFn()
				r.InstanceID = ""
				return r
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing vpc id",
			req: func() OpenTunnelEC2Request {
				r := baseReqFn()
				r.VPCID = ""
				return r
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing EC2SSHLoginUser",
			req: func() OpenTunnelEC2Request {
				r := baseReqFn()
				r.EC2SSHLoginUser = ""
				return r
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "missing EC2Address",
			req: func() OpenTunnelEC2Request {
				r := baseReqFn()
				r.EC2Address = ""
				return r
			},
			errCheck: isBadParamErrFn,
		},
		{
			name: "invalid port (only 22 and 3389 are allowed)",
			req: func() OpenTunnelEC2Request {
				r := baseReqFn()
				r.EC2Address = "127.0.0.1:5432"
				return r
			},
			errCheck: isBadParamErrFn,
		},
		{
			name:     "fill defaults",
			req:      baseReqFn,
			errCheck: require.NoError,
			reqWithDefaults: OpenTunnelEC2Request{
				Region:             "us-east-1",
				InstanceID:         "i-123",
				VPCID:              "vpc-id",
				EC2SSHLoginUser:    "ec2-user",
				EC2Address:         "127.0.0.1:22",
				ec2OpenSSHPort:     "22",
				ec2PrivateHostname: "127.0.0.1",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.req()
			err := r.CheckAndSetDefaults()
			tt.errCheck(t, err)

			if err != nil {
				return
			}
			require.Empty(t, cmp.Diff(tt.reqWithDefaults, r, cmpopts.IgnoreFields(OpenTunnelEC2Request{}, "ec2OpenSSHPort", "ec2PrivateHostname", "websocketCustomCA")))
			require.Equal(t, tt.reqWithDefaults.ec2PrivateHostname, r.ec2PrivateHostname)
			require.Equal(t, tt.reqWithDefaults.ec2OpenSSHPort, r.ec2OpenSSHPort)
		})
	}
}

func TestOpenTunnelEC2(t *testing.T) {
	ctx := context.Background()

	// ec2Listener emulates the TCP server on the EC2 instance
	// This listener will receive a connection from the EC2 Instance Connect Endpoint service
	ec2Listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer ec2Listener.Close()

	_, ec2ListenerPort, err := net.SplitHostPort(ec2Listener.Addr().String())
	require.NoError(t, err)
	validEC2Ports = append(validEC2Ports, ec2ListenerPort)

	// Emulate the EC2 Instance Connect Endpoint Service: an HTTP/websocket server
	//
	// Receives an HTTP request and upgrades it into a websocket connection C-WS
	//   - reads a message from C-WS - M1
	//   - starts a tcp connection from websocket into ec2 instance - C-EC2
	//   - writes M1 into C-EC2
	//   - reads M2 from C-EC2
	//   - writes M2 into the C-WS
	upgrader := websocket.Upgrader{}
	eiceWebsocketServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Log("upgrade error:", err)
			return
		}
		defer c.Close()

		_, message, err := c.ReadMessage()
		if err != nil {
			t.Log("read message error:", err)
			return
		}

		ec2Client, err := net.Dial("tcp", ec2Listener.Addr().String())
		if err != nil {
			t.Log("ec2 dial error:", err)
			return
		}
		defer ec2Client.Close()

		if _, err := ec2Client.Write(message); err != nil {
			t.Log("write into ec2 error:", err)
			return
		}

		bs := make([]byte, 4)
		if _, err := ec2Client.Read(bs); err != nil {
			t.Log("read from ec2 error:", err)
			return
		}

		if err := c.WriteMessage(websocket.BinaryMessage, bs); err != nil {
			t.Log("write into websocket error:", err)
		}
	}))
	defer eiceWebsocketServer.Close()

	eiceHostURL, err := url.Parse(eiceWebsocketServer.URL)
	require.NoError(t, err)

	m := &mockOpenTunnelEC2Client{
		ices: []ec2types.Ec2InstanceConnectEndpoint{
			{
				DnsName:                   aws.String(eiceHostURL.Host),
				InstanceConnectEndpointId: aws.String("eice-123"),
			},
		},
	}

	resp, err := OpenTunnelEC2(ctx, m, OpenTunnelEC2Request{
		EC2SSHLoginUser:   "os-user",
		Region:            "us-east-1",
		InstanceID:        "i-123",
		VPCID:             "vpc-123",
		EC2Address:        ec2Listener.Addr().String(),
		websocketCustomCA: eiceWebsocketServer.Certificate(),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	t.Run("ssh signer public key and os user matches what was sent to AWS", func(t *testing.T) {
		require.NotNil(t, resp.SSHSigner)

		sshPublicKeyFromSigner := string(ssh.MarshalAuthorizedKey(resp.SSHSigner.PublicKey()))

		require.Equal(t, sshPublicKeyFromSigner, m.sshKeySent)
		require.Equal(t, "os-user", m.sshForUserSent)
	})

	// This test sends a ping from local listener to the EC2 Instance Connect endpoint
	// Which sends it to the EC2 Instance, and it replies back the pong
	// The EICE then receives the pong and sends it back to the local listener.
	t.Run("connect over websocket", func(t *testing.T) {
		// emulate EC2 Instance
		go func() {
			// accept the connection from the EC2 side
			ec2LocalConnection, err := ec2Listener.Accept()
			assert.NoError(t, err)
			defer ec2LocalConnection.Close()

			bs := make([]byte, 4)
			ec2LocalConnection.Read(bs)
			assert.Equal(t, "ping", string(bs))

			_, err = ec2LocalConnection.Write([]byte("pong"))
			assert.NoError(t, err)
		}()
		_, err = resp.Tunnel.Write([]byte("ping"))
		require.NoError(t, err)

		bs := make([]byte, 4)
		_, err = resp.Tunnel.Read(bs)
		require.NoError(t, err)
		require.Equal(t, "pong", string(bytes.Trim(bs, "\x00")))

		resp.Tunnel.Close()
	})
}

type mockOpenTunnelEC2Client struct {
	ices           []ec2types.Ec2InstanceConnectEndpoint
	sshKeySent     string
	sshForUserSent string
}

func (m *mockOpenTunnelEC2Client) DescribeInstanceConnectEndpoints(ctx context.Context, params *ec2.DescribeInstanceConnectEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstanceConnectEndpointsOutput, error) {
	return &ec2.DescribeInstanceConnectEndpointsOutput{
		InstanceConnectEndpoints: m.ices,
	}, nil
}

func (m *mockOpenTunnelEC2Client) SendSSHPublicKey(ctx context.Context, params *ec2instanceconnect.SendSSHPublicKeyInput, optFns ...func(*ec2instanceconnect.Options)) (*ec2instanceconnect.SendSSHPublicKeyOutput, error) {
	m.sshKeySent = *params.SSHPublicKey
	m.sshForUserSent = *params.InstanceOSUser
	return nil, nil
}

func (m *mockOpenTunnelEC2Client) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, nil
}
