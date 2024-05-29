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
	"bytes"
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
)

// DiagRequest returns a diagnostics hook callback that will send the passed requests using a roundtripper generated from the settings and log httptrace events in the returned bytes.
func (settings *HTTPTransportSettings) DiagRequests(reqs []*http.Request, opts ...TransportOption) func() []byte {
	if settings == nil {
		return func() []byte {
			return []byte(`error: nil httpcommon.HTTPTransportSettings`)
		}
	}
	if len(reqs) == 0 {
		return func() []byte {
			return []byte(`error: 0 requests`)
		}
	}
	return func() []byte {
		var b bytes.Buffer
		rt, err := settings.RoundTripper(opts...)
		if err != nil {
			b.WriteString("unable to get roundtripper: " + err.Error())
			return b.Bytes()
		}
		logger := log.New(&b, "", log.LstdFlags|log.Lmicroseconds|log.LUTC)
		if settings.TLS == nil {
			logger.Print("No TLS settings")
		} else {
			logger.Print("TLS settings detected")
		}
		logger.Printf("Proxy disable=%v url=%s", settings.Proxy.Disable, settings.Proxy.URL)

		ct := &httptrace.ClientTrace{
			GetConn: func(hostPort string) {
				logger.Printf("GetConn called for %q", hostPort)
			},
			GotConn: func(connInfo httptrace.GotConnInfo) {
				logger.Printf("GotConn for %q", connInfo.Conn.RemoteAddr())
			},
			GotFirstResponseByte: func() {
				logger.Print("Response started")
			},
			Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
				logger.Printf("Got info response status=%d, headers=%v", code, header)
				return nil
			},
			DNSStart: func(info httptrace.DNSStartInfo) {
				logger.Printf("Starting DNS lookup for %q", info.Host)
			},
			DNSDone: func(info httptrace.DNSDoneInfo) {
				logger.Printf("Done DNS lookup: %+v", info)
			},
			ConnectStart: func(network, addr string) {
				logger.Printf("Connection started to %s:%s", network, addr)
			},
			ConnectDone: func(network, addr string, err error) {
				logger.Printf("Connection to %s:%s done, err: %v", network, addr, err)
			},
			TLSHandshakeStart: func() {
				logger.Print("TLS handshake starting")
			},
			TLSHandshakeDone: func(state tls.ConnectionState, err error) {
				logger.Printf("TLS handshake done. state=%+v err=%v", state, err)
			},
			WroteHeaders: func() {
				logger.Printf("Wrote request headers")
			},
			Wait100Continue: func() {
				logger.Printf("Waiting for continue")
			},
			WroteRequest: func(info httptrace.WroteRequestInfo) {
				logger.Printf("Wrote request err=%v", info.Err)
			},
		}
		for i, req := range reqs {
			logger.Printf("Request %d to %s starting", i, req.URL.String())
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), ct))
			if resp, err := rt.RoundTrip(req); err != nil {
				logger.Printf("request %d error: %v", i, err)
			} else {
				resp.Body.Close()
				logger.Printf("request %d successful.", i)
			}
		}
		return b.Bytes()
	}
}
