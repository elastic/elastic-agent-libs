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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/json"
	"github.com/elastic/pkcs8"
)

const (
	testCert = `-----BEGIN CERTIFICATE-----
MIIDCjCCAfKgAwIBAgITJ706Mu2wJlKckpIvkWxEHvEyijANBgkqhkiG9w0BAQsF
ADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwIBcNMTkwNzIyMTkyOTA0WhgPMjExOTA2
MjgxOTI5MDRaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBANce58Y/JykI58iyOXpxGfw0/gMvF0hUQAcUrSMxEO6n
fZRA49b4OV4SwWmA3395uL2eB2NB8y8qdQ9muXUdPBWE4l9rMZ6gmfu90N5B5uEl
94NcfBfYOKi1fJQ9i7WKhTjlRkMCgBkWPkUokvBZFRt8RtF7zI77BSEorHGQCk9t
/D7BS0GJyfVEhftbWcFEAG3VRcoMhF7kUzYwp+qESoriFRYLeDWv68ZOvG7eoWnP
PsvZStEVEimjvK5NSESEQa9xWyJOmlOKXhkdymtcUd/nXnx6UTCFgnkgzSdTWV41
CI6B6aJ9svCTI2QuoIq2HxX/ix7OvW1huVmcyHVxyUECAwEAAaNTMFEwHQYDVR0O
BBYEFPwN1OceFGm9v6ux8G+DZ3TUDYxqMB8GA1UdIwQYMBaAFPwN1OceFGm9v6ux
8G+DZ3TUDYxqMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAG5D
874A4YI7YUwOVsVAdbWtgp1d0zKcPRR+r2OdSbTAV5/gcS3jgBJ3i1BN34JuDVFw
3DeJSYT3nxy2Y56lLnxDeF8CUTUtVQx3CuGkRg1ouGAHpO/6OqOhwLLorEmxi7tA
H2O8mtT0poX5AnOAhzVy7QW0D/k4WaoLyckM5hUa6RtvgvLxOwA0U+VGurCDoctu
8F4QOgTAWyh8EZIwaKCliFRSynDpv3JTUwtfZkxo6K6nce1RhCWFAsMvDZL8Dgc0
yvgJ38BRsFOtkRuAGSf6ZUwTO8JJRRIFnpUzXflAnGivK9M13D5GEQMmIl6U9Pvk
sxSmbIUfc2SGJGCJD4I=
-----END CERTIFICATE-----`
)

// test TLS config loading
func load(yamlStr string) (*Config, error) {
	var cfg Config
	config, err := config.NewConfigWithYAML([]byte(yamlStr), "")
	if err != nil {
		return nil, err
	}

	if err = config.Unpack(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func mustLoad(t *testing.T, yamlStr string) *Config {
	cfg, err := load(yamlStr)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// copied from config.fromConfig
func cfgConvert(in *ucfg.Config) *config.C {
	return (*config.C)(in)
}

func loadJSON(jsonStr string) (*Config, error) {
	var cfg Config
	uc, err := json.NewConfig([]byte(jsonStr), ucfg.PathSep("."), ucfg.VarExp)
	if err != nil {
		return nil, err
	}

	c := cfgConvert(uc)

	if err = c.Unpack(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func loadServerConfigJSON(jsonStr string) (*ServerConfig, error) {
	var cfg ServerConfig
	uc, err := json.NewConfig([]byte(jsonStr), ucfg.PathSep("."), ucfg.VarExp)
	if err != nil {
		return nil, err
	}

	c := cfgConvert(uc)

	if err = c.Unpack(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func mustLoadServerConfigJSON(t *testing.T, jsonStr string) *ServerConfig {
	t.Helper()
	cfg, err := loadServerConfigJSON(jsonStr)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeTestFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
	return f.Name()
}

const (
	blockTypePKCS1 int = iota
	blockTypePKCS8
	blockTypePKCS1Encrypted
	blockTypePKCS8Encrypted
)

// Setup key+cert pair for the tests
func makeKeyCertPair(t *testing.T, blockType int, password string) (string, string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var block *pem.Block
	switch blockType {
	case blockTypePKCS1:
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}
	case blockTypePKCS8:
		b, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		}
	case blockTypePKCS1Encrypted:
		var err error
		block, err = x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), []byte(password), x509.PEMCipherAES256)
		require.NoError(t, err)
	case blockTypePKCS8Encrypted:
		//TODO: this uses an elastic implementation of pkcs8 as the stdlib does not support password protected pkcs8
		b, err := pkcs8.MarshalPrivateKey(key, []byte(password), nil)
		require.NoError(t, err)
		block = &pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: b,
		}
	}

	keyPem := pem.EncodeToMemory(block)
	tml := x509.Certificate{
		SerialNumber: new(big.Int),
		Subject:      pkix.Name{CommonName: "commonName"},
	}
	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	require.NoError(t, err)
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	return string(keyPem), string(certPem)
}
