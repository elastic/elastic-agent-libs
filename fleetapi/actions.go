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

import (
	"encoding/json"
	"time"
)

const (
	ActionTypeUnknown              = "UNKNOWN"
	ActionTypeUpgrade              = "UPGRADE"
	ActionTypeUnenroll             = "UNENROLL"
	ActionTypePolicyChange         = "POLICY_CHANGE"
	ActionTypePolicyReassign       = "POLICY_REASSIGN"
	ActionTypeSettings             = "SETTINGS"
	ActionTypeInputAction          = "INPUT_ACTION"
	ActionTypeCancel               = "CANCEL"
	ActionTypeDiagnostics          = "REQUEST_DIAGNOSTICS"
	ActionTypeMigrate              = "MIGRATE"
	ActionTypePrivilegeLevelChange = "PRIVILEGE_LEVEL_CHANGE"
)

// Action represents the base fields of a Fleet action returned in a checkin
// response. Both the full Elastic Agent and lightweight emulators (e.g. Horde
// drones) receive actions in this shape; each consumer interprets the Data
// payload according to its own needs.
type Action struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	InputType   string          `json:"input_type,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
	CreatedAt   time.Time       `json:"created_at,omitempty"`
	StartTime   *time.Time      `json:"start_time,omitempty"`
	Expiration  *time.Time      `json:"expiration,omitempty"`
	Traceparent string          `json:"traceparent,omitempty"`
}

// Signed contains the signed data and signature for action verification.
type Signed struct {
	Data      string `json:"data"`
	Signature string `json:"signature"`
}
