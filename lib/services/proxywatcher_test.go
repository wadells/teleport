/*
Copyright 2021 Gravitational, Inc.

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

package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

var _ types.Events = (*errorWatcher)(nil)

type errorWatcher struct {
}

func (e errorWatcher) GetProxies() ([]types.Server, error) {
	return nil, nil
}

func (e errorWatcher) NewWatcher(context.Context, types.Watch) (types.Watcher, error) {
	return nil, errors.New("watcher error")
}

var _ services.ProxyWatcherClient = (*nopProxyGetter)(nil)

type nopProxyGetter struct {
}

func (n nopProxyGetter) NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error) {
	panic("implement me")
}

func (n nopProxyGetter) GetProxies() ([]types.Server, error) {
	return nil, nil
}

func TestResourceWatcher_Backoff(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := clockwork.NewFakeClock()

	w, err := services.NewProxyWatcher(services.ProxyWatcherConfig{
		Context:        ctx,
		Component:      "test",
		Clock:          clock,
		MaxRetryPeriod: defaults.MaxWatcherBackoff,
		Client:         &errorWatcher{},
		ProxiesC:       make(chan []types.Server, 1),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	step := w.MaxRetryPeriod / 5.0
	for i := 0; i < 5; i++ {
		// wait for watcher to reload
		select {
		case duration := <-w.ResetC:
			stepMin := step * time.Duration(i) / 2
			stepMax := step * time.Duration(i+1)

			require.GreaterOrEqual(t, duration, stepMin)
			require.LessOrEqual(t, duration, stepMax)
			// add some extra to the duration to ensure the retry occurs
			clock.Advance(duration * 3)
		case <-time.After(time.Minute):
			t.Fatalf("timeout waiting for reset")
		}
	}
}

func TestProxyWatcher(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	bk, err := lite.NewWithConfig(ctx, lite.Config{
		Path:             t.TempDir(),
		PollStreamPeriod: 200 * time.Millisecond,
	})
	require.NoError(t, err)

	type client struct {
		services.Presence
		types.Events
	}

	presence := local.NewPresenceService(bk)
	w, err := services.NewProxyWatcher(services.ProxyWatcherConfig{
		Context:        ctx,
		Component:      "test",
		MaxRetryPeriod: 200 * time.Millisecond,
		Client: &client{
			Presence: presence,
			Events:   local.NewEventsService(bk),
		},
		ProxiesC: make(chan []types.Server, 10),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })

	// Since no proxy is yet present, the ProxyWatcher should immediately
	// yield back to its retry loop.
	select {
	case <-w.ResetC:
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for ProxyWatcher reset.")
	}

	// Add a proxy server.
	proxy := newProxyServer(t, "proxy1", "127.0.0.1:2023")
	require.NoError(t, presence.UpsertProxy(proxy))

	// The first event is always the current list of proxies.
	select {
	case changeset := <-w.ProxiesC:
		require.Len(t, changeset, 1)
		require.Empty(t, resourceDiff(changeset[0], proxy))
	case <-w.Done():
		t.Fatal("Watcher has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the first event.")
	}

	// Add a second proxy.
	proxy2 := newProxyServer(t, "proxy2", "127.0.0.1:2023")
	require.NoError(t, presence.UpsertProxy(proxy2))

	// Watcher should detect the proxy list change.
	select {
	case changeset := <-w.ProxiesC:
		require.Len(t, changeset, 2)
	case <-w.Done():
		t.Fatal("Watcher has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}

	// Delete the first proxy.
	require.NoError(t, presence.DeleteProxy(proxy.GetName()))

	// Watcher should detect the proxy list change.
	select {
	case changeset := <-w.ProxiesC:
		require.Len(t, changeset, 1)
		require.Empty(t, resourceDiff(changeset[0], proxy2))
	case <-w.Done():
		t.Fatal("Watcher has unexpectedly exited.")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for the update event.")
	}
}

func resourceDiff(res1, res2 types.Resource) string {
	return cmp.Diff(res1, res2,
		cmpopts.IgnoreFields(types.Metadata{}, "ID"),
		cmpopts.EquateEmpty())
}

func newProxyServer(t *testing.T, name, addr string) types.Server {
	server := &types.ServerV2{
		Kind:    types.KindProxy,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:   name,
			Labels: map[string]string{},
		},
		Spec: types.ServerSpecV2{
			Addr:       addr,
			PublicAddr: addr,
		},
	}
	require.NoError(t, server.CheckAndSetDefaults())
	return server
}
