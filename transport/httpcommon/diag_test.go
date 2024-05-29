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

package httpcommon

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/stretchr/testify/require"
)

func Test_HTTPTransportSettings_DiagRequests(t *testing.T) {
	t.Run("nil settings", func(t *testing.T) {
		var settings *HTTPTransportSettings
		p := settings.DiagRequests(nil)()
		require.Equal(t, []byte(`error: nil httpcommon.HTTPTransportSettings`), p)
	})

	t.Run("no requests", func(t *testing.T) {
		settings := &HTTPTransportSettings{}
		p := settings.DiagRequests(nil)()
		require.Equal(t, []byte(`error: 0 requests`), p)
	})

	t.Run("request OK", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		settings := DefaultHTTPTransportSettings()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		p := settings.DiagRequests([]*http.Request{req})()

		require.Contains(t, string(p), "No TLS settings")
		require.Contains(t, string(p), "request 0 successful.")
	})

	t.Run("TLS server with no settings", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		settings := DefaultHTTPTransportSettings()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		p := settings.DiagRequests([]*http.Request{req})()

		require.Contains(t, string(p), "No TLS settings")
		require.Contains(t, string(p), "request 0 error:")
	})

	t.Run("TLS server with settings", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ca := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: srv.TLS.Certificates[0].Certificate[0],
		})
		require.NotEmpty(t, ca)
		settings := DefaultHTTPTransportSettings()
		settings.TLS = &tlscommon.Config{
			CAs: []string{string(ca)},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		p := settings.DiagRequests([]*http.Request{req})()

		require.Contains(t, string(p), "TLS settings detected")
		require.Contains(t, string(p), "request 0 successful.")
	})
}
