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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

//
// Create Policy
//

const (
	agentPoliciesApi     = "/agent_policies"
	enrollmentApiKeysApi = "/enrollment_api_keys"
)

type MonitoringEnabledOption string

const (
	MonitoringEnabledLogs    MonitoringEnabledOption = "logs"
	MonitoringEnabledMetrics MonitoringEnabledOption = "metrics"
)

type CreatePolicyRequest struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	Namespace         string                    `json:"namespace"`
	Description       string                    `json:"description"`
	MonitoringEnabled []MonitoringEnabledOption `json:"monitoring_enabled"`
}

type CreatePolicyResponse struct {
	ID                string                    `json:"id,omitempty"`
	Name              string                    `json:"name"`
	Description       string                    `json:"description"`
	Namespace         string                    `json:"namespace"`
	IsManaged         bool                      `json:"is_managed"`
	Status            string                    `json:"status"`
	MonitoringEnabled []MonitoringEnabledOption `json:"monitoring_enabled"`
}

func (client *Client) CreatePolicy(request CreatePolicyRequest) (*CreatePolicyResponse, error) {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal create policy request into JSON: %w", err)
	}

	statusCode, respBody, err := client.Request(http.MethodPost, agentPoliciesApi, nil, nil, bytes.NewReader(reqBody))
	if statusCode != 200 {
		return nil, fmt.Errorf("unable to create policy; API returned status code [%d] and body [%s]", statusCode, string(respBody))
	}

	var resp struct {
		Item CreatePolicyResponse `json:"item"`
	}

	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unable to parse create policy API responses: %w", err)
	}

	return &resp.Item, nil
}

//
// Create Enrollment API Key
//

type CreateEnrollmentAPIKeyRequest struct {
	Name     string `json:"name"`
	PolicyID string `json:"policy_id"`
}

type CreateEnrollmentAPIKeyResponse struct {
	Active   bool   `json:"active"`
	APIKey   string `json:"api_key"`
	APIKeyID string `json:"api_key_id"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	PolicyID string `json:"policy_id"`
}

func (client *Client) CreateEnrollmentAPIKey(request CreateEnrollmentAPIKeyRequest) (*CreateEnrollmentAPIKeyResponse, error) {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal create enrollment API key request into JSON: %w", err)
	}

	statusCode, respBody, err := client.Request(http.MethodPost, enrollmentApiKeysApi, nil, nil, bytes.NewReader(reqBody))
	if statusCode != 200 {
		return nil, fmt.Errorf("unable to create enrollment API key; API returned status code [%d] and body [%s]", statusCode, string(respBody))
	}

	var resp struct {
		Item CreateEnrollmentAPIKeyResponse `json:"item"`
	}

	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unable to parse create enrollment API key API responses: %w", err)
	}

	return &resp.Item, nil
}
