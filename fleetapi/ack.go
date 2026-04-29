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

package fleetapi

import "encoding/json"

// AckEvent is an event sent in an ACK request to Fleet Server.
type AckEvent struct {
	EventType       string                 `json:"type"`
	SubType         string                 `json:"subtype"`
	Timestamp       string                 `json:"timestamp"`
	ActionID        string                 `json:"action_id"`
	AgentID         string                 `json:"agent_id"`
	Message         string                 `json:"message,omitempty"`
	Payload         json.RawMessage        `json:"payload,omitempty"`
	Data            json.RawMessage        `json:"data,omitempty"`
	ActionInputType string                 `json:"action_input_type,omitempty"`
	ActionData      json.RawMessage        `json:"action_data,omitempty"`
	ActionResponse  map[string]interface{} `json:"action_response,omitempty"`
	StartedAt       string                 `json:"started_at,omitempty"`
	CompletedAt     string                 `json:"completed_at,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

// AckRequest is the payload sent to Fleet Server's ack endpoint.
type AckRequest struct {
	Events []AckEvent `json:"events"`
}

// AckResponseItem is the status of an individual ack event.
type AckResponseItem struct {
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
}

// AckResponse is the response from Fleet Server's ack endpoint.
type AckResponse struct {
	Action string            `json:"action"`
	Errors bool              `json:"errors,omitempty"`
	Items  []AckResponseItem `json:"items,omitempty"`
}
