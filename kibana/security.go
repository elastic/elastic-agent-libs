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
	"context"
	"fmt"
	"net/http"
)

const (
	serviceTokenAPI = "/_security/service/elastic/%s/credential/token"
)

type ServiceTokenResp struct {
	Token struct {
		Value string `json:"value"`
	} `json:"token"`
}

// GetServiceToken creates a new service token in the elastic namespace for the specified service and returns the token value.
// ref: https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-service-token.html
func (client *Client) GetServiceToken(ctx context.Context, service string) (string, error) {
	path := fmt.Sprintf(serviceTokenAPI, service)
	resp, err := client.Connection.SendWithContext(ctx, http.MethodPost, path, nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("unable to get service token for %q: %w", service, err)
	}
	defer resp.Body.Close()
	var tokenResp ServiceTokenResp
	err = readJSONResponse(resp, &tokenResp)
	return tokenResp.Token.Value, err
}
