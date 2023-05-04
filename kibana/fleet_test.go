// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package kibana

import (
	"fmt"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFleetCreatePolicy(t *testing.T) {
	const (
		policyID          = "test-policy-id"
		policyName        = "test policy"
		policyDescription = "a policy used for testing"
	)

	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case agentPoliciesAPI:
			respBody := fmt.Sprintf(
				`{"item":{"id":"%s","name":"%s","description":"%s"}}`,
				policyID, policyName, policyDescription,
			)
			_, _ = w.Write([]byte(respBody))
		}
	}

	client, err := createTestServerAndClient(handler)
	require.NoError(t, err)
	require.NotNil(t, client)

	req := CreatePolicyRequest{
		Name:        policyName,
		Description: policyDescription,
		MonitoringEnabled: []MonitoringEnabledOption{
			MonitoringEnabledLogs,
			MonitoringEnabledMetrics,
		},
	}
	resp, err := client.CreatePolicy(req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Equal(t, resp.ID, policyID)
	require.Equal(t, resp.Name, policyName)
	require.Equal(t, resp.Description, policyDescription)
}

func createTestServerAndClient(handler http.HandlerFunc) (*Client, error) {
	kibanaTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case statusAPI:
			_, _ = w.Write([]byte(`{"version":{"number":"1.2.3-beta","build_snapshot":true}}`))
		default:
			handler(w, r)
		}
	}))

	cfg := fmt.Sprintf(`
protocol: http
host: %s
`, kibanaTS.Listener.Addr().String())
	return NewKibanaClient(config.MustNewConfigFrom(cfg), binaryName, v, commit, buildTime)
}
