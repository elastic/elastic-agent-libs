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

package tlscommon

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func Test_ServerConfig_Serialization_ClientAuth(t *testing.T) {
	tests := []struct {
		name       string
		cfg        ServerConfig
		clientAuth TLSClientAuth
	}{{
		name: "with ca",
		cfg: ServerConfig{
			Certificate: CertificateConfig{
				Certificate: "/path/to/cert.crt",
				Key:         "/path/to/cert.key",
			},
			CAs: []string{"/path/to/ca.crt"},
		},
		clientAuth: TLSClientAuthRequired,
	}, {
		name: "no ca",
		cfg: ServerConfig{
			Certificate: CertificateConfig{
				Certificate: "/path/to/cert.crt",
				Key:         "/path/to/cert.key",
			},
		},
		clientAuth: TLSClientAuthNone,
	}, {
		name: "with ca and client auth none",
		cfg: ServerConfig{
			Certificate: CertificateConfig{
				Certificate: "/path/to/cert.crt",
				Key:         "/path/to/cert.key",
			},
			CAs:        []string{"/path/to/ca.crt"},
			ClientAuth: TLSClientAuthNone,
		},
		clientAuth: TLSClientAuthNone, // FIXME test fails, it serializes to required
	}, {
		name: "no ca and client auth none",
		cfg: ServerConfig{
			Certificate: CertificateConfig{
				Certificate: "/path/to/cert.crt",
				Key:         "/path/to/cert.key",
			},
			ClientAuth: TLSClientAuthNone,
		},
		clientAuth: TLSClientAuthNone,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := yaml.Marshal(&tc.cfg)
			require.NoError(t, err)
			scfg := mustLoadServerConfig(t, string(p))
			require.Equal(t, tc.clientAuth, scfg.ClientAuth)
		})
	}
}
