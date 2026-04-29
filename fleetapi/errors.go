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
	"errors"
	"net/http"
)

var (
	ErrTooManyRequests    = errors.New("too many requests received (429)")
	ErrConnRefused        = errors.New("connection refused")
	ErrTemporaryServerErr = errors.New("temporary server error, please retry later")
	ErrInvalidToken       = errors.New("invalid enrollment token")
	ErrInvalidAPIKey      = errors.New("invalid api key to authenticate with fleet")
)

// TemporaryServerErrorCodes maps HTTP status codes that indicate a transient
// Fleet Server failure. Clients should retry the request with backoff.
var TemporaryServerErrorCodes = map[int]string{
	http.StatusBadGateway:         "BadGateway",
	http.StatusServiceUnavailable: "ServiceUnavailable",
	http.StatusGatewayTimeout:     "GatewayTimeout",
}
