package redact

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

const redactedURL = REDACTED + ":" + REDACTED

func TestRedact(t *testing.T) {
	const markerPrefix = "__mark_redact_"

	tests := map[string]struct {
		input  map[any]any
		opts   []RedactOption
		expect map[any]any
	}{
		"nil map": {
			input:  nil,
			expect: nil,
		},
		"empty map": {
			input:  map[any]any{},
			expect: map[any]any{},
		},
		"no redactions": {
			input: map[any]any{
				"type":      "elasticsearch",
				"namespace": "default",
				"count":     int64(5),
			},
			expect: map[any]any{
				"type":      "elasticsearch",
				"namespace": "default",
				"count":     int64(5),
			},
		},
		"sensitive keys are redacted": {
			input: map[any]any{
				"api_key":     "secret",
				"password":    "secret",
				"passphrase":  "secret",
				"token":       "secret",
				"certificate": "secret",
				"secret":      "secret",
				"X-App-Auth":  "secret",
				"safe":        "value",
			},
			expect: map[any]any{
				"api_key":     REDACTED,
				"password":    REDACTED,
				"passphrase":  REDACTED,
				"token":       REDACTED,
				"certificate": REDACTED,
				"secret":      REDACTED,
				"X-App-Auth":  REDACTED,
				"safe":        "value",
			},
		},
		"keys are matched case insensitively": {
			input: map[any]any{
				"API_KEY":     "secret",
				"PassWord":    "secret",
				"PASSPHRASE":  "secret",
				"tOkEn":       "secret",
				"Certificate": "secret",
			},
			expect: map[any]any{
				"API_KEY":     REDACTED,
				"PassWord":    REDACTED,
				"PASSPHRASE":  REDACTED,
				"tOkEn":       REDACTED,
				"Certificate": REDACTED,
			},
		},
		"URL credentials are redacted": {
			input: map[any]any{
				"url":       "https://user:pass@example.com/path",
				"other_url": "https://example.com/path",
				"plain":     "not a url",
			},
			expect: map[any]any{
				"url":       "https://" + redactedURL + "@example.com/path",
				"other_url": "https://example.com/path",
				"plain":     "not a url",
			},
		},
		"URL credentials in slice elements are redacted": {
			input: map[any]any{
				"urls": []any{
					"https://user:pass@my-url1",
					"https://user:pass@my-url2",
					"https://my-url3",
				},
			},
			expect: map[any]any{
				"urls": []any{
					"https://" + redactedURL + "@my-url1",
					"https://" + redactedURL + "@my-url2",
					"https://my-url3",
				},
			},
		},
		"sensitive key wins over URL redaction": {
			input: map[any]any{
				"secret_url": "https://user:pass@example.com",
			},
			expect: map[any]any{
				"secret_url": REDACTED,
			},
		},
		"nested map[string]any is redacted recursively": {
			input: map[any]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type":     "elasticsearch",
						"api_key":  "secret",
						"hosts":    []any{"https://user:pass@es:9200"},
						"username": "user",
					},
				},
			},
			expect: map[any]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type":     "elasticsearch",
						"api_key":  REDACTED,
						"hosts":    []any{"https://" + redactedURL + "@es:9200"},
						"username": "user",
					},
				},
			},
		},
		"nested map[any]any is redacted recursively": {
			input: map[any]any{
				"outputs": map[any]any{
					"default": map[any]any{
						"type":    "elasticsearch",
						"api_key": "secret",
					},
				},
			},
			expect: map[any]any{
				"outputs": map[any]any{
					"default": map[any]any{
						"type":    "elasticsearch",
						"api_key": REDACTED,
					},
				},
			},
		},
		"slice items that are maps are redacted recursively": {
			input: map[any]any{
				"inputs": []any{
					map[string]any{
						"type":    "test",
						"api_key": "secret",
					},
					map[string]any{
						"type":     "test",
						"password": "secret",
					},
				},
			},
			expect: map[any]any{
				"inputs": []any{
					map[string]any{
						"type":    "test",
						"api_key": REDACTED,
					},
					map[string]any{
						"type":     "test",
						"password": REDACTED,
					},
				},
			},
		},
		"deeply nested ssl key in inputs is redacted": {
			input: map[any]any{
				"inputs": []any{
					map[string]any{
						"ssl": map[string]any{
							"certificate": "cert1",
							"key":         "key1",
						},
						"nested": map[string]any{
							"ssl": map[string]any{
								"certificate": "cert2",
								"key":         "key2",
							},
						},
						"slice": []any{
							map[string]any{
								"ssl": map[string]any{
									"certificate": "cert3",
									"key":         "key3",
								},
							},
						},
					},
				},
			},
			expect: map[any]any{
				"inputs": []any{
					map[string]any{
						"ssl": map[string]any{
							"certificate": REDACTED,
							"key":         REDACTED,
						},
						"nested": map[string]any{
							"ssl": map[string]any{
								"certificate": REDACTED,
								"key":         REDACTED,
							},
						},
						"slice": []any{
							map[string]any{
								"ssl": map[string]any{
									"certificate": REDACTED,
									"key":         REDACTED,
								},
							},
						},
					},
				},
			},
		},
		"name/value entries are redacted when name indicates a secret": {
			input: map[any]any{
				"headers": []any{
					map[string]any{
						"name":  "Authorization",
						"value": "Bearer secret-token",
					},
					map[string]any{
						"name":  "X-Custom",
						"value": "harmless",
					},
				},
			},
			expect: map[any]any{
				"headers": []any{
					map[string]any{
						"name":  "Authorization",
						"value": REDACTED,
					},
					map[string]any{
						"name":  "X-Custom",
						"value": "harmless",
					},
				},
			},
		},
		"redaction markers are processed when prefix is configured": {
			input: map[any]any{
				"inputs": []any{
					map[string]any{
						"type":                        "test_input",
						"redactKey":                   "secretValue",
						markerPrefix + "redactKey":    true,
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{
						"type":                       "elasticsearch",
						"api_key":                    "alreadyMatched",
						"redactOtherKey":             "secretOutputValue",
						markerPrefix + "redactOtherKey": true,
					},
				},
			},
			opts: []RedactOption{WithMarkerPrefix(markerPrefix)},
			expect: map[any]any{
				"inputs": []any{
					map[string]any{
						"type":      "test_input",
						"redactKey": REDACTED,
					},
				},
				"outputs": map[string]any{
					"default": map[string]any{
						"type":           "elasticsearch",
						"api_key":        REDACTED,
						"redactOtherKey": REDACTED,
					},
				},
			},
		},
		"redaction markers in nested slice items are processed": {
			input: map[any]any{
				"id": "test-policy",
				"inputs": []any{
					map[string]any{
						"type": "httpjson",
						"streams": []any{
							map[string]any{
								"request": map[string]any{
									"transforms": []any{
										map[string]any{
											"set": map[string]any{
												"target":                  "header.Authorization",
												"value":                   "SSWS this-should-be-redacted",
												markerPrefix + "value":    true,
											},
										},
										map[string]any{
											"set": map[string]any{
												"target": "url.params.limit",
												"value":  "1000",
											},
										},
									},
								},
							},
							map[string]any{
								"mock_stream_config": map[string]any{
									"kind": map[string]any{
										"string_value": "mock_stream_config_name",
									},
								},
								markerPrefix + "mock_stream_config": true,
							},
						},
					},
				},
			},
			opts: []RedactOption{WithMarkerPrefix(markerPrefix)},
			expect: map[any]any{
				"id": "test-policy",
				"inputs": []any{
					map[string]any{
						"type": "httpjson",
						"streams": []any{
							map[string]any{
								"request": map[string]any{
									"transforms": []any{
										map[string]any{
											"set": map[string]any{
												"target": "header.Authorization",
												"value":  REDACTED,
											},
										},
										map[string]any{
											"set": map[string]any{
												"target": "url.params.limit",
												"value":  "1000",
											},
										},
									},
								},
							},
							map[string]any{
								"mock_stream_config": REDACTED,
							},
						},
					},
				},
			},
		},
		"redaction markers are ignored when no prefix is configured": {
			input: map[any]any{
				"benign":                "value",
				markerPrefix + "benign": true,
			},
			expect: map[any]any{
				"benign":                "value",
				markerPrefix + "benign": true,
			},
		},
		"ignored keys are not redacted": {
			input: map[any]any{
				"routekey":      "should-not-redact",
				"my_secret_key": "redact-me",
				"safe":          "value",
			},
			opts: []RedactOption{WithIgnoreKeys("routekey")},
			expect: map[any]any{
				"routekey":      "should-not-redact",
				"my_secret_key": REDACTED,
				"safe":          "value",
			},
		},
		"ignored keys and markers coexist": {
			input: map[any]any{
				"routekey":                 "should-not-redact",
				"keepme":                   "value",
				markerPrefix + "keepme":    true,
				"api_key":                  "secret",
			},
			opts: []RedactOption{
				WithIgnoreKeys("routekey"),
				WithMarkerPrefix(markerPrefix),
			},
			expect: map[any]any{
				"routekey": "should-not-redact",
				"keepme":   REDACTED,
				"api_key":  REDACTED,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var errOut bytes.Buffer
			opts := append([]RedactOption{WithErrorOutput(&errOut)}, tc.opts...)

			Redact(tc.input, opts...)

			assert.Equal(t, tc.expect, tc.input)
			assert.Empty(t, errOut.String(), "no warnings expected")
		})
	}
}

func TestRedactURL(t *testing.T) {
	tests := map[string]struct {
		input    string
		expect   string
		redacted bool
	}{
		"plain string": {
			input:    "not a url",
			expect:   "not a url",
			redacted: false,
		},
		"url without credentials": {
			input:    "https://example.com/path",
			expect:   "https://example.com/path",
			redacted: false,
		},
		"url with credentials": {
			input:    "https://user:pass@example.com/path",
			expect:   "https://" + redactedURL + "@example.com/path",
			redacted: true,
		},
		"url with username only": {
			input:    "https://user@example.com",
			expect:   "https://" + redactedURL + "@example.com",
			redacted: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, redacted := redactURL(tc.input)
			assert.Equal(t, tc.expect, got)
			assert.Equal(t, tc.redacted, redacted)
		})
	}
}

func TestRedactKey(t *testing.T) {
	tests := map[string]struct {
		key        string
		ignoreKeys []string
		expect     bool
	}{
		"empty":              {key: "", expect: false},
		"safe":               {key: "type", expect: false},
		"auth substring":     {key: "X-Authentication", expect: true},
		"certificate":        {key: "certificate", expect: true},
		"passphrase":         {key: "passphrase", expect: true},
		"password":           {key: "password", expect: true},
		"token":              {key: "token", expect: true},
		"key substring":      {key: "api_key", expect: true},
		"secret substring":   {key: "client_secret", expect: true},
		"uppercase matches":  {key: "PASSWORD", expect: true},
		"mixed case matches": {key: "ApiKey", expect: true},
		"ignored exact":      {key: "routekey", ignoreKeys: []string{"routekey"}, expect: false},
		"ignored is case sensitive": {
			// "RouteKey" still matches the redaction rule via "key";
			// ignoreKeys check is exact-match before lowercasing.
			key: "RouteKey", ignoreKeys: []string{"routekey"}, expect: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ro := &redactOptions{ignoreKeys: tc.ignoreKeys}
			assert.Equal(t, tc.expect, redactKey(tc.key, ro))
		})
	}
}
