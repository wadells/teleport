/**
 * Copyright 2022 Gravitational, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchSearch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		wantMatch  bool
		fieldVals  []string
		searchVals []string
		customFn   func(v string) bool
	}{
		{
			name:       "no match",
			fieldVals:  []string{"foo", "bar", "baz"},
			searchVals: []string{"cat"},
			customFn: func(v string) bool {
				return false
			},
		},
		{
			name:       "no match for partial match",
			fieldVals:  []string{"foo"},
			searchVals: []string{"foo", "dog"},
		},
		{
			name:       "no match for partial custom match",
			fieldVals:  []string{"foo", "bar", "baz"},
			searchVals: []string{"foo", "bee", "rat"},
			customFn: func(v string) bool {
				return v == "bee"
			},
		},
		{
			name:       "no match for search phrase",
			fieldVals:  []string{"foo", "dog", "dog foo", "foodog"},
			searchVals: []string{"foo dog"},
		},
		{
			name:       "match",
			wantMatch:  true,
			fieldVals:  []string{"foo", "bar", "baz"},
			searchVals: []string{"baz"},
		},
		{
			name:      "match with nil search values",
			wantMatch: true,
		},
		{
			name:       "match with repeat search vals",
			wantMatch:  true,
			fieldVals:  []string{"foo", "bar", "baz"},
			searchVals: []string{"foo", "foo", "baz"},
		},
		{
			name:       "match for a list of search vals contained within one field value",
			wantMatch:  true,
			fieldVals:  []string{"foo barbaz"},
			searchVals: []string{"baz", "foo", "bar"},
		},
		{
			name:       "match with mix of single vals and phrases",
			wantMatch:  true,
			fieldVals:  []string{"foo baz", "bar"},
			searchVals: []string{"baz", "foo", "foo baz", "bar"},
		},
		{
			name:       "match ignore case",
			wantMatch:  true,
			fieldVals:  []string{"FOO barBaz"},
			searchVals: []string{"baZ", "foo", "BaR"},
		},
		{
			name:       "match with custom match",
			wantMatch:  true,
			fieldVals:  []string{"foo", "bar", "baz"},
			searchVals: []string{"foo", "bar", "tunnel"},
			customFn: func(v string) bool {
				return v == "tunnel"
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			matched := MatchSearch(tc.fieldVals, tc.searchVals, tc.customFn)

			switch {
			case tc.wantMatch:
				require.True(t, matched)
			default:
				require.False(t, matched)
			}
		})
	}
}

func TestMatchSearch_ResourceSpecific(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// searchNotDefined refers to resources where the searcheable field values are not defined.
		searchNotDefined   bool
		matchingSearchVals []string
		newResource        func() ResourceWithLabels
	}{
		{
			name:               "node",
			matchingSearchVals: []string{"foo", "bar"},
			newResource: func() ResourceWithLabels {
				server, err := NewServer("_", KindNode, ServerSpecV2{
					Hostname: "foo",
					Addr:     "bar",
				})
				require.NoError(t, err)

				return server
			},
		},
		{
			name:               "node using tunnel",
			matchingSearchVals: []string{"tunnel"},
			newResource: func() ResourceWithLabels {
				server, err := NewServer("_", KindNode, ServerSpecV2{
					UseTunnel: true,
				})
				require.NoError(t, err)

				return server
			},
		},
		{
			name:               "windows desktop",
			matchingSearchVals: []string{"foo", "bar"},
			newResource: func() ResourceWithLabels {
				desktop, err := NewWindowsDesktopV3("foo", nil, WindowsDesktopSpecV3{
					Addr: "bar",
				})
				require.NoError(t, err)

				return desktop
			},
		},
		{
			name:               "application",
			matchingSearchVals: []string{"foo", "bar", "baz"},
			newResource: func() ResourceWithLabels {
				app, err := NewAppV3(Metadata{
					Name:        "foo",
					Description: "bar",
				}, AppSpecV3{
					PublicAddr: "baz",
					URI:        "_",
				})
				require.NoError(t, err)

				return app
			},
		},
		{
			name:               "kube cluster",
			matchingSearchVals: []string{"foo"},
			newResource: func() ResourceWithLabels {
				kc, err := NewKubernetesClusterV3FromLegacyCluster("_", &KubernetesCluster{
					Name: "foo",
				})
				require.NoError(t, err)

				return kc
			},
		},
		{
			name:               "database",
			matchingSearchVals: []string{"foo", "bar", "baz", DatabaseTypeRedshift},
			newResource: func() ResourceWithLabels {
				db, err := NewDatabaseV3(Metadata{
					Name:        "foo",
					Description: "bar",
				}, DatabaseSpecV3{
					Protocol: "baz",
					URI:      "_",
					AWS: AWS{
						Redshift: Redshift{
							ClusterID: "_",
						},
					},
				})
				require.NoError(t, err)

				return db
			},
		},
		{
			name:             "app server",
			searchNotDefined: true,
			newResource: func() ResourceWithLabels {
				appServer, err := NewAppServerV3(Metadata{
					Name: "_",
				}, AppServerSpecV3{
					HostID: "_",
					App:    &AppV3{Metadata: Metadata{Name: "_"}, Spec: AppSpecV3{URI: "_"}},
				})
				require.NoError(t, err)

				return appServer
			},
		},
		{
			name:             "kube server",
			searchNotDefined: true,
			newResource: func() ResourceWithLabels {
				kubeServer, err := NewServer("_", KindKubeService, ServerSpecV2{})
				require.NoError(t, err)

				return kubeServer
			},
		},
		{
			name:             "db server",
			searchNotDefined: true,
			newResource: func() ResourceWithLabels {
				dbServer, err := NewDatabaseServerV3(Metadata{
					Name: "_",
				}, DatabaseServerSpecV3{
					HostID:   "_",
					Hostname: "_",
				})
				require.NoError(t, err)

				return dbServer
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resource := tc.newResource()

			// Nil search values, should always return true
			match := resource.MatchSearch(nil)
			require.True(t, match)

			switch {
			case tc.searchNotDefined:
				// Non empty values, should return false
				match := resource.MatchSearch([]string{"_"})
				require.False(t, match)
			default:
				// Test no match.
				match := resource.MatchSearch([]string{"foo", "llama"})
				require.False(t, match)

				// Test match.
				match = resource.MatchSearch(tc.matchingSearchVals)
				require.True(t, match)
			}
		})
	}
}
