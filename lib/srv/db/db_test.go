/*
Copyright 2020-2021 Gravitational, Inc.

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

package db

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/gravitational/teleport/api/types"
	"github.com/stretchr/testify/require"
)

// TestContextConnections starts a default test context, begins handling connections,
// then closes and ensures all connections were closed (zero open TCP file descriptors).
func TestContextConnections(t *testing.T) {
	var lsof lsofCmd
	if !lsof.Available() {
		t.Skip()
	}
	t.Cleanup(func() { lsof.TestTCP(t, os.Getpid()) })

	testCtx := setupTestContext(context.Background(), t)
	go testCtx.startHandlingConnections()
}

func TestMongoConnections(t *testing.T) {
	var lsof lsofCmd
	if !lsof.Available() {
		t.Skip()
	}
	t.Cleanup(func() { lsof.TestTCP(t, os.Getpid()) })

	ctx := context.Background()
	testCtx := setupTestContext(ctx, t, withSelfHostedMongo("mongo"))
	go testCtx.startHandlingConnections()

	alice := "alice"
	admin := "admin"
	wildcard := []string{types.Wildcard}
	testCtx.createUserAndRole(ctx, t, alice, admin, wildcard, wildcard)

	client, err := testCtx.mongoClient(ctx, alice, "mongo", admin)
	require.NoError(t, err)
	client.Disconnect(ctx)
}

type lsofCmd struct {
	path string
}

func (ls *lsofCmd) Available() bool {
	const notfound = "\x00"
	if len(ls.path) == 0 {
		path, err := exec.LookPath("lsof")
		if err != nil {
			ls.path = notfound
		} else {
			ls.path = path
		}
	}
	return ls.path != notfound
}

func (ls *lsofCmd) Cmd(args ...string) *exec.Cmd {
	return exec.Command(ls.path, args...)
}

func (ls *lsofCmd) TCP(pid int) [][]byte {
	if !ls.Available() {
		return nil
	}
	cmd := ls.Cmd("-a", "-p", strconv.Itoa(pid), "-i", "TCP")
	raw, err := cmd.Output()
	if err != nil || len(raw) == 0 {
		// lsof returns exit status of 1 when nothing is found :/
		// assume things worked but didn't find any connections
		// TODO: find a better way to handle this
		return nil
	}
	lines := bytes.Split(raw, []byte("\n"))
	if len(lines) <= 2 {
		// first line is header row and last line is blank
		return nil
	}
	return lines[1 : len(lines)-1]
}

func (ls *lsofCmd) TestTCP(t *testing.T, pid int) {
	conns := ls.TCP(pid)
	if len(conns) > 0 {
		t.Errorf("%d connections were not closed", len(conns))
		if !testing.Verbose() {
			return
		}
		for _, conn := range conns {
			t.Log(string(conn))
		}
	}
}
