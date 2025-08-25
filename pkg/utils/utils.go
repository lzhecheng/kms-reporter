package utils

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Sample key: /registry/secrets/kube-system/bootstrap-token-ldeus6
// Sample value: k8s:enc:kms:v2:kmsprovider1:<some-value>

const (
	etcdObjectValueKmsEncryptedPrefix = "k8s:enc:kms:"
)

// ParseEtcdObject parses etcd key and value to extract encryption status, secret name, and sequence number.
// k: etcd key (e.g., "/registry/secrets/kube-system/bootstrap-token-ldeus6")
// v: etcd value (e.g., "k8s:enc:kms:v2:kmsprovider1:<some-value>")
// Returns: encrypted (bool), secret (string), seq (int), err (error)
func ParseEtcdObject(k, v string, kmsProviderName string) (bool, string, int, error) {
	// Check if the value is encrypted
	encrypted := strings.HasPrefix(v, etcdObjectValueKmsEncryptedPrefix)

	// Parse the secret name from the key
	// key format: /registry/secret/default/mysecret
	keyParts := strings.Split(k, "/")
	if len(keyParts) < 5 {
		return encrypted, "", 0, fmt.Errorf("invalid key format: %s", k)
	}
	secret := fmt.Sprintf("%s/%s", keyParts[3], keyParts[4])

	// Parse the sequence number from the value if encrypted
	seq := 0
	if encrypted {
		// value format: k8s:enc:kms:v2:kmsprovider1:<some-value>
		valueParts := strings.Split(v, ":")
		if len(valueParts) < 6 {
			return encrypted, secret, 0, fmt.Errorf("invalid encrypted value format: %s", v)
		}

		seqStr := strings.TrimPrefix(valueParts[4], kmsProviderName)
		seqInt, err := strconv.Atoi(seqStr)
		if err != nil {
			return encrypted, secret, 0, fmt.Errorf("failed to convert seq to int: %w", err)
		}
		seq = seqInt
	}

	return encrypted, secret, seq, nil
}

type Marshaller interface {
	Marshal(v any) ([]byte, error)
}

type JSONMarshaller struct{}

func (j JSONMarshaller) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}
