package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEtcdObject(t *testing.T) {
	tests := []struct {
		name              string
		key               string
		value             string
		kmsProviderName   string
		expectedEncrypted bool
		expectedSecret    string
		expectedSeq       int
		expectedError     string
	}{
		{
			name:              "encrypted secret with valid format",
			key:               "/registry/secrets/default/mysecret",
			value:             "k8s:enc:kms:v2:kmsprovider1:encrypted-data-here",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: true,
			expectedSecret:    "default/mysecret",
			expectedSeq:       1,
		},
		{
			name:              "encrypted secret with different provider sequence",
			key:               "/registry/secrets/kube-system/bootstrap-token",
			value:             "k8s:enc:kms:v2:kmsprovider5:another-encrypted-value",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: true,
			expectedSecret:    "kube-system/bootstrap-token",
			expectedSeq:       5,
		},
		{
			name:              "encrypted secret with sequence 0",
			key:               "/registry/secrets/namespace1/secret-name",
			value:             "k8s:enc:kms:v2:kmsprovider0:encrypted-content",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: true,
			expectedSecret:    "namespace1/secret-name",
			expectedSeq:       0,
		},
		{
			name:              "encrypted secret with large sequence number",
			key:               "/registry/secrets/test/large-seq",
			value:             "k8s:enc:kms:v2:kmsprovider123:data",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: true,
			expectedSecret:    "test/large-seq",
			expectedSeq:       123,
		},
		{
			name:              "unencrypted secret",
			key:               "/registry/secrets/default/plaintext-secret",
			value:             "plain-text-secret-data",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: false,
			expectedSecret:    "default/plaintext-secret",
			expectedSeq:       0,
		},
		{
			name:              "unencrypted secret with complex data",
			key:               "/registry/secrets/kube-system/config-secret",
			value:             "{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"data\":{\"key\":\"value\"}}",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: false,
			expectedSecret:    "kube-system/config-secret",
			expectedSeq:       0,
		},
		{
			name:            "invalid key format - too few parts",
			key:             "/registry/secrets/default",
			value:           "some-value",
			kmsProviderName: "kmsprovider",
			expectedError:   "invalid key format",
		},
		{
			name:            "invalid key format - empty parts",
			key:             "/registry/secrets//mysecret",
			value:           "some-value",
			kmsProviderName: "kmsprovider",
			expectedSecret:  "/mysecret", // This will still parse but with empty namespace
		},
		{
			name:            "invalid key format - completely malformed",
			key:             "invalid-key",
			value:           "some-value",
			kmsProviderName: "kmsprovider",
			expectedError:   "invalid key format",
		},
		{
			name:              "encrypted value with invalid format - too few colons",
			key:               "/registry/secrets/default/mysecret",
			value:             "k8s:enc:kms:v2:kmsprovider1",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: true,
			expectedSecret:    "default/mysecret",
			expectedError:     "invalid encrypted value format",
		},
		{
			name:              "encrypted value with invalid provider format",
			key:               "/registry/secrets/default/mysecret",
			value:             "k8s:enc:kms:v2:invalidprovider:data",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: true,
			expectedSecret:    "default/mysecret",
			expectedError:     "failed to convert seq to int",
		},
		{
			name:              "encrypted value with non-numeric sequence",
			key:               "/registry/secrets/default/mysecret",
			value:             "k8s:enc:kms:v2:kmsprovidabc:data",
			kmsProviderName:   "kmsprovid", // Note: different prefix to test parsing
			expectedEncrypted: true,
			expectedSecret:    "default/mysecret",
			expectedError:     "failed to convert seq to int",
		},
		{
			name:              "encrypted value with empty sequence",
			key:               "/registry/secrets/default/mysecret",
			value:             "k8s:enc:kms:v2:kmsprovider:data",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: true,
			expectedSecret:    "default/mysecret",
			expectedError:     "failed to convert seq to int",
		},
		{
			name:              "edge case - key with many slashes",
			key:               "/registry/secrets/namespace/secret-with-many/slashes/in/name",
			value:             "unencrypted-data",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: false,
			expectedSecret:    "namespace/secret-with-many",
		},
		{
			name:            "edge case - empty key",
			key:             "",
			value:           "some-value",
			kmsProviderName: "kmsprovider",
			expectedError:   "invalid key format",
		},
		{
			name:              "edge case - empty value with valid key",
			key:               "/registry/secrets/default/mysecret",
			value:             "",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: false,
			expectedSecret:    "default/mysecret",
			expectedSeq:       0,
		},
		{
			name:              "encrypted secret with partial prefix match",
			key:               "/registry/secrets/default/mysecret",
			value:             "k8s:enc:something-else:data",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: false,
			expectedSecret:    "default/mysecret",
			expectedSeq:       0,
		},
		{
			name:              "case sensitivity test",
			key:               "/registry/secrets/Default/MySecret",
			value:             "k8s:enc:kms:v2:kmsprovider2:data",
			kmsProviderName:   "kmsprovider",
			expectedEncrypted: true,
			expectedSecret:    "Default/MySecret",
			expectedSeq:       2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, secret, seq, err := ParseEtcdObject(tt.key, tt.value, tt.kmsProviderName)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedEncrypted, encrypted)
				assert.Equal(t, tt.expectedSecret, secret)
				assert.Equal(t, tt.expectedSeq, seq)
			}
		})
	}
}

func TestJSONMarshaller(t *testing.T) {
	tests := []struct {
		name           string
		input          interface{}
		expectedOutput string
		expectedError  bool
	}{
		{
			name:           "marshal simple string",
			input:          "hello world",
			expectedOutput: `"hello world"`,
		},
		{
			name:           "marshal integer",
			input:          42,
			expectedOutput: `42`,
		},
		{
			name:           "marshal boolean",
			input:          true,
			expectedOutput: `true`,
		},
		{
			name:           "marshal slice",
			input:          []string{"a", "b", "c"},
			expectedOutput: `["a","b","c"]`,
		},
		{
			name: "marshal struct",
			input: struct {
				Name  string `json:"name"`
				Age   int    `json:"age"`
				Valid bool   `json:"valid"`
			}{
				Name:  "test",
				Age:   25,
				Valid: true,
			},
			expectedOutput: `{"name":"test","age":25,"valid":true}`,
		},
		{
			name:           "marshal map",
			input:          map[string]int{"key1": 1, "key2": 2},
			expectedOutput: `{"key1":1,"key2":2}`,
		},
		{
			name:           "marshal nil",
			input:          nil,
			expectedOutput: `null`,
		},
		{
			name:           "marshal empty string",
			input:          "",
			expectedOutput: `""`,
		},
		{
			name:           "marshal empty slice",
			input:          []string{},
			expectedOutput: `[]`,
		},
		{
			name:           "marshal empty map",
			input:          map[string]string{},
			expectedOutput: `{}`,
		},
		{
			name: "marshal complex nested structure",
			input: map[string]interface{}{
				"users": []map[string]interface{}{
					{"name": "alice", "age": 30, "active": true},
					{"name": "bob", "age": 25, "active": false},
				},
				"metadata": map[string]string{
					"version": "1.0",
					"env":     "prod",
				},
			},
			expectedOutput: `{"metadata":{"env":"prod","version":"1.0"},"users":[{"active":true,"age":30,"name":"alice"},{"active":false,"age":25,"name":"bob"}]}`,
		},
		{
			name:          "marshal unmarshalable type",
			input:         make(chan int),
			expectedError: true,
		},
		{
			name:          "marshal function - should error",
			input:         func() {},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marshaller := JSONMarshaller{}
			result, err := marshaller.Marshal(tt.input)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.JSONEq(t, tt.expectedOutput, string(result))
			}
		})
	}
}

func TestMarshaller_Interface(t *testing.T) {
	// Test that JSONMarshaller implements Marshaller interface
	var marshaller Marshaller = JSONMarshaller{}

	testData := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	result, err := marshaller.Marshal(testData)
	assert.NoError(t, err)
	assert.Contains(t, string(result), `"key1":"value1"`)
	assert.Contains(t, string(result), `"key2":123`)
	assert.Contains(t, string(result), `"key3":true`)

	// Verify it's valid JSON
	expected := `{"key1":"value1","key2":123,"key3":true}`
	assert.JSONEq(t, expected, string(result))
}

// Benchmark tests for performance
func BenchmarkParseEtcdObject_Encrypted(b *testing.B) {
	key := "/registry/secrets/default/benchmark-secret"
	value := "k8s:enc:kms:v2:kmsprovider5:encrypted-benchmark-data"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = ParseEtcdObject(key, value, "kmsprovider5")
	}
}

func BenchmarkParseEtcdObject_Unencrypted(b *testing.B) {
	key := "/registry/secrets/default/benchmark-secret"
	value := "unencrypted-benchmark-data"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = ParseEtcdObject(key, value, "kmsprovider")
	}
}

func BenchmarkJSONMarshaller(b *testing.B) {
	marshaller := JSONMarshaller{}
	testData := map[string]interface{}{
		"name":    "benchmark-test",
		"count":   100,
		"active":  true,
		"tags":    []string{"tag1", "tag2", "tag3"},
		"details": map[string]string{"env": "test", "version": "1.0"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = marshaller.Marshal(testData)
	}
}

// Property-based testing helpers
func TestParseEtcdObject_Properties(t *testing.T) {
	t.Run("encrypted values always return encrypted=true", func(t *testing.T) {
		testCases := []string{
			"k8s:enc:kms:v2:kmsprovider1:data1",
			"k8s:enc:kms:v2:kmsprovider999:data2",
			"k8s:enc:kms:v2:kmsprovider0:data3",
		}

		for _, value := range testCases {
			encrypted, _, _, err := ParseEtcdObject("/registry/secrets/ns/name", value, "kmsprovider")
			if err == nil {
				assert.True(t, encrypted, "encrypted value should return encrypted=true")
			}
		}
	})

	t.Run("non-encrypted values always return encrypted=false", func(t *testing.T) {
		testCases := []string{
			"plain-text-data",
			"k8s:enc:aes:data", // Different encryption type
			"some-other-prefix:data",
			"",
		}

		for _, value := range testCases {
			encrypted, _, _, err := ParseEtcdObject("/registry/secrets/ns/name", value, "kmsprovider")
			if err == nil {
				assert.False(t, encrypted, "non-encrypted value should return encrypted=false")
			}
		}
	})

	t.Run("valid keys always produce namespace/name format", func(t *testing.T) {
		testCases := []struct {
			key            string
			expectedSecret string
		}{
			{"/registry/secrets/default/mysecret", "default/mysecret"},
			{"/registry/secrets/kube-system/token", "kube-system/token"},
			{"/registry/secrets/a/b", "a/b"},
		}

		for _, tc := range testCases {
			_, secret, _, err := ParseEtcdObject(tc.key, "any-value", "kmsprovider")
			if err == nil {
				assert.Equal(t, tc.expectedSecret, secret)
			}
		}
	})
}
