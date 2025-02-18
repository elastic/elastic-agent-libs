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

//go:build requirefips

package tlscommon

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestFIPSCertifacteAndKeys tests cert + key pair loading when in FIPS mode
// It will ensure encrypted keys fail, and loading from disk or inline will work for other pairs
func TestFIPSCertificateAndKeys(t *testing.T) {
	// Write certificate to a temporary file.
	certFile := writeTestFile(t, testCert)
	key := `
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXHufGPycpCOfI
sjl6cRn8NP4DLxdIVEAHFK0jMRDup32UQOPW+DleEsFpgN9/ebi9ngdjQfMvKnUP
Zrl1HTwVhOJfazGeoJn7vdDeQebhJfeDXHwX2DiotXyUPYu1ioU45UZDAoAZFj5F
KJLwWRUbfEbRe8yO+wUhKKxxkApPbfw+wUtBicn1RIX7W1nBRABt1UXKDIRe5FM2
MKfqhEqK4hUWC3g1r+vGTrxu3qFpzz7L2UrRFRIpo7yuTUhEhEGvcVsiTppTil4Z
HcprXFHf5158elEwhYJ5IM0nU1leNQiOgemifbLwkyNkLqCKth8V/4sezr1tYblZ
nMh1cclBAgMBAAECggEBAKdP5jyOicqknoG9/G564RcDsDyRt64NuO7I6hBg7SZx
Jn7UKWDdFuFP/RYtoabn6QOxkVVlydp5Typ3Xu7zmfOyss479Q/HIXxmmbkD0Kp0
eRm2KN3y0b6FySsS40KDRjKGQCuGGlNotW3crMw6vOvvsLTlcKgUHF054UVCHoK/
Piz7igkDU7NjvJeha53vXL4hIjb10UtJNaGPxIyFLYRZdRPyyBJX7Yt3w8dgz8WM
epOPu0dq3bUrY3WQXcxKZo6sQjE1h7kdl4TNji5jaFlvD01Y8LnyG0oThOzf0tve
Gaw+kuy17gTGZGMIfGVcdeb+SlioXMAAfOps+mNIwTECgYEA/gTO8W0hgYpOQJzn
BpWkic3LAoBXWNpvsQkkC3uba8Fcps7iiEzotXGfwYcb5Ewf5O3Lrz1EwLj7GTW8
VNhB3gb7bGOvuwI/6vYk2/dwo84bwW9qRWP5hqPhNZ2AWl8kxmZgHns6WTTxpkRU
zrfZ5eUrBDWjRU2R8uppgRImsxMCgYEA2MxuL/C/Ko0d7XsSX1kM4JHJiGpQDvb5
GUrlKjP/qVyUysNF92B9xAZZHxxfPWpdfGGBynhw7X6s+YeIoxTzFPZVV9hlkpAA
5igma0n8ZpZEqzttjVdpOQZK8o/Oni/Q2S10WGftQOOGw5Is8+LY30XnLvHBJhO7
TKMurJ4KCNsCgYAe5TDSVmaj3dGEtFC5EUxQ4nHVnQyCpxa8npL+vor5wSvmsfUF
hO0s3GQE4sz2qHecnXuPldEd66HGwC1m2GKygYDk/v7prO1fQ47aHi9aDQB9N3Li
e7Vmtdn3bm+lDjtn0h3Qt0YygWj+wwLZnazn9EaWHXv9OuEMfYxVgYKpdwKBgEze
Zy8+WDm5IWRjn8cI5wT1DBT/RPWZYgcyxABrwXmGZwdhp3wnzU/kxFLAl5BKF22T
kRZ+D+RVZvVutebE9c937BiilJkb0AXLNJwT9pdVLnHcN2LHHHronUhV7vetkop+
kGMMLlY0lkLfoGq1AxpfSbIea9KZam6o6VKxEnPDAoGAFDCJm+ZtsJK9nE5GEMav
NHy+PwkYsHhbrPl4dgStTNXLenJLIJ+Ke0Pcld4ZPfYdSyu/Tv4rNswZBNpNsW9K
0NwJlyMBfayoPNcJKXrH/csJY7hbKviAHr1eYy9/8OL0dHf85FV+9uY5YndLcsDc
nygO9KTJuUiBrLr0AHEnqko=
-----END PRIVATE KEY-----
`

	t.Run("embed", func(t *testing.T) {
		// Create a dummy configuration and append the CA after.
		cfg, err := load(`
enabled: true
verification_mode: null
certificate: null
key: null
key_passphrase: null
certificate_authorities:
cipher_suites: null
curve_types: null
supported_protocols: null
  `)
		require.NoError(t, err)

		cfg.Certificate.Certificate = testCert
		cfg.Certificate.Key = key

		tlsC, err := LoadTLSConfig(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, tlsC)
	})

	t.Run("embed small key", func(t *testing.T) {
		// Create a dummy configuration and append the CA after.
		cfg, err := load(`
enabled: true
verification_mode: null
certificate: null
key: null
key_passphrase: null
certificate_authorities:
cipher_suites: null
curve_types: null
supported_protocols: null
  `)
		require.NoError(t, err)

		certificate := `
-----BEGIN CERTIFICATE-----
MIIBmzCCAUCgAwIBAgIRAOQpDyaFimzmueynALHkFEcwCgYIKoZIzj0EAwIwJjEk
MCIGA1UEChMbVEVTVCAtIEVsYXN0aWMgSW50ZWdyYXRpb25zMB4XDTIxMDIwMjE1
NTkxMFoXDTQxMDEyODE1NTkxMFowJjEkMCIGA1UEChMbVEVTVCAtIEVsYXN0aWMg
SW50ZWdyYXRpb25zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBc7UEvBd+5SG
Z6QQfgBaPh/VAlf7ovpa/wfSmbHfBhee+dTvdAO1p90lannCkZmc7OfWAlQ1eTgJ
QW668CJwE6NPME0wDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MAwGA1UdEwEB/wQCMAAwGAYDVR0RBBEwD4INZWxhc3RpYy1hZ2VudDAKBggqhkjO
PQQDAgNJADBGAiEAhpGWL4lxsdb3+hHv0y4ppw6B7IJJLCeCwHLyHt2Dkx4CIQD6
OEU+yuHzbWa18JVkHafxwnpwQmxwZA3VNitM/AyGTQ==
-----END CERTIFICATE-----
`
		key := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFDQJ1CPLXrUbUFqj
ED8dqsGuVQdcPK7CHpsCeTtAgQqhRANCAAQFztQS8F37lIZnpBB+AFo+H9UCV/ui
+lr/B9KZsd8GF5751O90A7Wn3SVqecKRmZzs59YCVDV5OAlBbrrwInAT
-----END PRIVATE KEY-----
`
		cfg.Certificate.Certificate = certificate
		cfg.Certificate.Key = key

		tlsC, err := LoadTLSConfig(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, tlsC)
	})

	t.Run("embed encrypted PKCS#1 key", func(t *testing.T) {
		// Create a dummy configuration and append the CA after.
		cfg, err := load(`
enabled: true
verification_mode: null
certificate: null
key: null
key_passphrase: null
certificate_authorities:
cipher_suites: null
curve_types: null
supported_protocols: null
  `)
		require.NoError(t, err)

		certificate := `
-----BEGIN CERTIFICATE-----
MIIDJDCCAgygAwIBAgIUMRBqXpkJyFUbOXUUqm8nlYtbu9swDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZTJlLXRlc3QtY2EwHhcNMjMwNjIwMTMxODMzWhcNMjQw
NjEwMTMxODMzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCntmIIrkiNNKIVsIwUu69iZUK46ReJ/1N+erul+m4l
WytVYWEx461fAqJYbEbSNkFg8FE3hG34cl9WarRXxoITqRFH6Mbrs/veLimEMmg7
jGdhrXqm2Xa90TgOT56tJfHVcT4idOLxTgLY0rtXjJ01yub4rVp/R4kBIWY8Jq7X
vY+s+zr2TwMsx478Awa5kpbKK/e3TnGmjeyhBeNEEZ6EH3r8dmAMbFsNNkR+GYIX
ahIC3t52RzeZoHUpcdFSphTViA2rK5NxQSC+VaYTHAOdRVCeZiWntmDa7h1uo1e5
Vxkbkm5V3tCIKdewrWNE6HyXd9WZnQTLX8DZMfdaMCeTAgMBAAGjbDBqMCgGA1Ud
EQQhMB+HBH8AAAGCCWxvY2FsaG9zdIIMZmxlZXQtc2VydmVyMB0GA1UdDgQWBBTi
ajrT7LSiAAOTz3X0iU45h0DggzAfBgNVHSMEGDAWgBS39ozxXHs37ebVk4bG5ahf
u5PQYTANBgkqhkiG9w0BAQsFAAOCAQEAqy2tehB0a1umUbUxtTmM64XxPmRVNQ7f
FGypeQLUdGJpueiEBL9o3FgFJGonjBJIDITkEHYuJ8/yBACjXPFc2uGCqB6UzfI/
skKb4JVVacM9eGaevPgXu143YvhEAYMaST1oo+iZKs4w2+nNx5y7F9B/a2yIE9H8
mrPVWmOCMtwHJrO7kF1ENDgHPkhoZFcpFhu3lzOY7mhpW5mPZPVs87ZmI75G7zMV
6c0prpPUojYpaZjKSpKTvy+XRFKBHk3MR2LG97GzQn6HRXYuIkihC1oiGgUAHdGz
AcV8KJqa/7XTTpvIzXePw9FtSSux5SkU6iKAKqwUt82D1E73bbppSg==
-----END CERTIFICATE-----
`
		//nolint:gosec // testing key
		key := `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D9241F0CD9554705DF245AE11F5D3631

I+Ozf9xbw5JvT7nIryNFa/bGzpi3i0DVzzcE2kGPdJrZT66y1xgEpcuCjgiAdkZz
NzqJqyuTMyeXAKP1kbdJpOzEr/snlw/PYg4iMTu0aW4so5VoS5upSlsKu1gd6b7e
i95oBcJnZ9GWLrnwYunEk3/ljzPczd3ywUY9QLZcqQT6KGR/ApqF+LXeD8lPpjxi
/CEbJpdh1jNzy5nGzF+WqL+z1/kaZM4/ahnWYgHV+o3vklv7L6uEM650Q2wL6mWE
95v+enRSB4Mg9KTT5478pysrFpNQi1GpcgVNNfnTrko9Ttlo1zW8//UTeBMvpMrb
Osv/MDBrbXPa3RZyxhUq73EFkZhRJCI6deryzpwQPycBvdPGFucbWt5I8bmcG3es
sfNNLlKVtkrW6t1NPM/LCk9MLT1/fO1dtR+uIJr5egGP1RRfdkvEmDK5nsKxMEUq
6dNw74R0zFCn/8dXTPPQcU42tn0gajP93t8WS4+aXWD+y2kytviFcvZ3ZEdRA9cl
Z3uGLW+CRI48KIR4F0i831fFVCiyfHnfxZJNZJ6KL7W2GkKFgJJ37BGsZGEpL7UR
nLVUNkj03e4CxiUDvkvlvMvI4/oeGNJ3nbtMgFND+XQVXWidDI/Sh5I3cNfs/Hpu
h+ePQ+HgEFTLimSqxH2nW3tczg0OKGU4fyoQ6+D1fvR5VRLlBTIWkuzxnsPduvSt
YK02pmqkrRYqpoYIu+g8bLjwekoLNsjT9K+Ua6dySADE0bov50zjcOYyIp0KL3+2
+6+938HigGMrCWq3gDspOsW5wTzXAF9o7CLlkwCgqoMr2Ov6PCfyETUUfEG5Nhus
1MmKjWyOg85TXggcQdEKJVCdC3q8V7vAYjSHBEr86taoQRz6us8uFqPJffZCk1VQ
hP7w32jneCbjlll5vUWh/UQ5P8A1bmR32TGbd0woPIb6VTrGyrPNYkU+VsL5GW0/
7ZyeYFAQpJrsg3Dizqi9M6TfK20G+dsiD9lGXPr7Iw++ai3uQVMIORkO0t8RWG4K
xmTS5bfSTiZ6ukK7Dl5T0/m1aNXS1aaQ0LjPi/INEttl/sKkQ9LhbWvJFfYseiPt
V4LTq0FG8bUzXsRGhMPA/osAlXtlu2BqR5PbUwmeb47J43VwUaHkfxB6llObEr7a
2CxS2T10QFYI9zG1JLhCYsfsqpX/BcKNcm3DWXdsmaLQsIsRkanOfItkJVNfRMNz
/p0MiEp2WtXcCjzjCyLKpLq5fPZeTq2HGSibgxPBtEsBre1UXErzAq3TK3jkwSRU
uNLravWUezdvpLY3HXoAh4UZViut1TmAqrxfM2IKmdSm3vtcmSd5BH777Dq/eK1K
z2mAIeqGbi0s+IUFsjnIp57Qzohpnvh2lyon8X8bBrFlLz9b7yKqqdYtczdCE9Z6
GbMk6EW8GjGwYqyEBQqHad/TDoxqG6qmKChxMsAAvcFFvqN/V+RIT1SjEp4F6pXV
aWowEutgPc3AMLhnIya1MfjmvmqWE/IiVWlD034Xe0djg4HxGh8hlOWBoHfkW62k
2GU0+4H1mDlMlkjHvU9E/veS0LjcQfj+5Bhjb/Ej3JwVGFrZs4OHqqqN72o0mOMc
-----END RSA PRIVATE KEY-----
`
		cfg.Certificate.Certificate = certificate
		cfg.Certificate.Key = key
		cfg.Certificate.Passphrase = "abcd1234"

		_, err = LoadTLSConfig(cfg)
		assert.ErrorIs(t, err, errors.ErrUnsupported)
	})

	t.Run("embed PKCS#8 key", func(t *testing.T) {
		// Create a dummy configuration and append the CA after.
		cfg, err := load(`
enabled: true
verification_mode: null
certificate: null
key: null
key_passphrase: null
certificate_authorities:
cipher_suites: null
curve_types: null
supported_protocols: null
  `)
		require.NoError(t, err)

		certificate := `
-----BEGIN CERTIFICATE-----
MIIDJDCCAgygAwIBAgIUSvcbYtICneFF1gQmn9nhwVTB18YwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZTJlLXRlc3QtY2EwHhcNMjMwNjIwMTUxNDQxWhcNMjQw
NjEwMTUxNDQxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDShtKeGJag0UdHg2v77vETkCSg881omMAtY/4DvyPl
vK3oUTt+9prtO2iGKyQK3dm3QKBTeVOhhlQvz61GqY9XM93mQ3OqOrT0r2omWHjF
JJmlOfmhS83oZldjaaB+1XHl7M2lMXZeLjbVMig0ROGu45o86db5Y39a5WhAeNq9
hYFhJ76E0c8D+2x5Fr2bv5LC05cWM2nOmYWBho2hry4syeT8u3pwUwKoH3EZkKhs
eDITZWX7Y7kKxHeRLPSywfxxLbYSRVH2zHAh3XlaLjSr6/loH3gEHbqn71J56NDv
gvZteGQc1OBHezFt+kiyMdnzBfRGbEQx8GrfsGl0O7bdAgMBAAGjbDBqMCgGA1Ud
EQQhMB+HBH8AAAGCCWxvY2FsaG9zdIIMZmxlZXQtc2VydmVyMB0GA1UdDgQWBBSe
bWzF3LSxLxz9SN+T9UQKZRHjrzAfBgNVHSMEGDAWgBSdgFGPj0HyR5OJV68/iQOC
O9FrCzANBgkqhkiG9w0BAQsFAAOCAQEAEkLTSRmihD9HF9jZEOD+G2jE+5Fr4A1V
c/Lm6f8KEKYguesktC+WmWFIH4/X56UmSrF9f2N8Iw1OYQK7wf0OBd6NYPY+uyPp
4RNWfqOrUq3p8u15eL2fbpPWymVzP1N9fZQ4b3+c8VlZydOzBWoEsrt9050SsHbe
DyN1BYaqIu8RJwvKsVyxOmHq6QOKt16CgdEnoNFxGspFdTAYArhaMehOneqzMPe3
jUkBaOWa4q1nXmUSTa2n5iUO9EzlEnN1l1qP4gBIG2sIpm35pPQB4X2TpsV6mldh
DP31Yq0Yk8hxK6bQ6pjzAkeoHXyW5QT3WnEkKXxiu774EQJFmsZAHA==
-----END CERTIFICATE-----
`
		key := `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI9DztFKiqGcsCAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBAh/QM2Am0LEVMtKiXTPDwSBIIE
0F8sa5rcpm5keNE4gZWrZcRQhM//qRpni4PdeQKRqvey8G69PfE+cxieunO41kTo
1q09TTSnCO7HT+YuwTM3o4QFcJ0ya907qEV7epbX3HGkl+YhjmzgTMYiylaC+C4y
x8oLhbPX5o9pwqEsbAd+Tz+HkUPyjjfg5uGbAAtOANSp66b77wANODw2Bk5VJga8
hZd+gEJOOOLmFmIB/VD823BAYFTSgMwKAV2STRH/+1Pu8xyw6R5gJ3ps22UzasWQ
JmNO8p0GBECE9FUx5/Fxt3av0mnkpYSedH/2FnSbD548XQQrcAhWftHl0xiOpcPc
wMUOMREXNMtNcX3O+JpX1DghDl+VlRR+0BqCM2W/qgy+9P+W/BeH95cied3zqlr1
gFriicuB5gfsMJdIxrP+w2ZpnD1IlQxTkBof55BtqHJTv1h3eoEBus+9msDsf1S/
Lcgo4T+xRU6wODn5TQ3kOq5TVVJWTaNOgbRiONBc4Z9G3Pz/LQLr3uKFHXaQWaRW
thtkBHhty9VXAyi2iJbEmLUEaMJkinYfkLDl/qwiGEK/T7FwB6S+kr2plFzx1ffL
FBWcXS+uhxkbVJ5NMh1FMcVQe1xS2LaMMkAiP6J3/tW80k3T9/Fv7BMQjDG8YlNC
npz7XIghuqWFDueSgqTvuPOPtV9tSUos388CoviZDjXOI1E/U5OvPBW0NubyNSyQ
MkFYhgR8ffnlHL0mI8xsWDnHYGNDnVCNXhrs4VZDxRd30srFo+0cFBX2EDw53+8d
ocqPydNHUEzT1plI9rRTH67k5LfCJ6jwtm5d5KomBD8u2TW1SQ76GA1F7y7mtyOY
rNlB2EL/bZWVsoNPCJ+4z5IO6wBssfwYy0n4TkGbtPnsIXExXu3itt7PQ+Qb+G5C
9G0C9OqefycoEdMK5cmOGQO5NWWlgTcfzpqTF3JBb34RenD9ZPaSlUglOu6teM0b
DIzzXecqKpPU53q4ALoqfANwxu8ZPMwUIoJvZ8PFGn7TB/j4yqZJEx31X4fnCLKO
3smMLlWAp2u0ZHb/+cloxFELfz6+WWzK7gYSH2k1aro6h1FzGTf0GHucijzBjU2T
UUnHdQizszgRYgC858lizz/DfcIOW1aM71m3I3fwW2ywJU1DMgrgSvH8UN/pLp/z
i3bJdsv2Ka8pDe0oCLUM01Ldna6ff3NcuRCBCREOUiozDrNUeJlKRMtYfMH3wz1b
lUxZTNopHsSqQyNyo+HQy/DmWqavb2fB6gnBuHk3NWRbw8eSllYzLX+Y79deBeke
LM9EGp3p5dS0JhQ/9a1p730R9KcipiuH86Qk3TbU71nWh1J10Kh6+q9df+w0iAin
AD58GtyL1LRGiEQ07jFrfodMEhNcL0tcn4V2AjAsils06pnAHZriHnAs2Cd6ZyNc
j1gmFY7d099M2hgAmsZimYduaD7PObq/8MzQq+yQ1ZFBzHjv7TB2Noa8p2NljKBL
YAPBOrtpnB2mCDeABjA4iJb5GZSco76wGAhy5UhaykIaIBRaqvtbLAi+HoPmEm6h
0Mn+uIGHPUzSC9dO85iOn3uZk7xRLCJTp5WOESaCAjxjaep6J3Y7qTTi7XyO7fV5
lQnRKskc+T5PeoAwdCtQ1RVCSXZNetXdPCj790BkNEt6
-----END ENCRYPTED PRIVATE KEY-----
`
		cfg.Certificate.Certificate = certificate
		cfg.Certificate.Key = key
		cfg.Certificate.Passphrase = "abcd1234"

		_, err = LoadTLSConfig(cfg)
		assert.ErrorIs(t, err, errors.ErrUnsupported)
	})

	t.Run("From disk", func(t *testing.T) {
		keyFile := writeTestFile(t, key)
		// Create a dummy configuration and append the CA after.
		cfg, err := load(`
enabled: true
verification_mode: null
certificate: null
key: null
key_passphrase: null
certificate_authorities:
cipher_suites: null
curve_types: null
supported_protocols: null
  `)
		require.NoError(t, err)

		cfg.Certificate.Certificate = certFile
		cfg.Certificate.Key = keyFile

		tlsC, err := LoadTLSConfig(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, tlsC)
	})
}
