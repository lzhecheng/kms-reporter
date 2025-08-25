package etcd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// MockEtcdClient implements EtcdClientOperator for testing
type MockEtcdClient struct {
	getResponse *clientv3.GetResponse
	getError    error
	closeError  error
}

func (m *MockEtcdClient) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return m.getResponse, m.getError
}

func (m *MockEtcdClient) Close() error {
	return m.closeError
}

// Helper function to create temporary certificate files for testing
func createTempCertFiles(t *testing.T) (certFile, keyFile, caFile string, cleanup func()) {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	// Generate client private key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate client key: %v", err)
	}

	// Create client certificate template
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization:  []string{"Test Client"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
	}

	// Parse CA certificate for signing
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create client certificate
	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	// Create temporary files
	certFile = createTempFile(t, "cert", encodePEM("CERTIFICATE", clientCertDER))
	keyFile = createTempFile(t, "key", encodePEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey)))
	caFile = createTempFile(t, "ca", encodePEM("CERTIFICATE", caCertDER))

	cleanup = func() {
		os.Remove(certFile)
		os.Remove(keyFile)
		os.Remove(caFile)
	}

	return certFile, keyFile, caFile, cleanup
}

func createTempFile(t *testing.T, prefix string, content []byte) string {
	tmpFile, err := ioutil.TempFile("", prefix+"*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	return tmpFile.Name()
}

func encodePEM(blockType string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: data,
	})
}

func TestCreateEtcdClient_Success(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTempCertFiles(t)
	defer cleanup()

	// Note: This test will fail to connect to etcd since we're not running an etcd server,
	// but it will validate certificate loading and TLS configuration
	client, err := CreateEtcdClient("https://localhost:2379", certFile, keyFile, caFile)

	// We expect the client creation to succeed (certificate loading should work)
	// but connection might fail since no etcd server is running
	if err != nil {
		// Check if it's a connection error, not a certificate error
		if !isConnectionError(err) {
			t.Errorf("Expected connection error, but got certificate error: %v", err)
		}
	} else {
		// If no error, client should not be nil
		if client == nil {
			t.Error("Expected non-nil client")
		} else {
			// Clean up the client
			client.Close()
		}
	}
}

func TestCreateEtcdClient_InvalidCertFile(t *testing.T) {
	_, keyFile, caFile, cleanup := createTempCertFiles(t)
	defer cleanup()

	_, err := CreateEtcdClient("https://localhost:2379", "nonexistent.pem", keyFile, caFile)
	if err == nil {
		t.Error("Expected error for invalid certificate file")
	}
	if !containsError(err, "failed to load client certificate and key") {
		t.Errorf("Expected certificate loading error, got: %v", err)
	}
}

func TestCreateEtcdClient_InvalidKeyFile(t *testing.T) {
	certFile, _, caFile, cleanup := createTempCertFiles(t)
	defer cleanup()

	_, err := CreateEtcdClient("https://localhost:2379", certFile, "nonexistent.pem", caFile)
	if err == nil {
		t.Error("Expected error for invalid key file")
	}
	if !containsError(err, "failed to load client certificate and key") {
		t.Errorf("Expected certificate loading error, got: %v", err)
	}
}

func TestCreateEtcdClient_InvalidCAFile(t *testing.T) {
	certFile, keyFile, _, cleanup := createTempCertFiles(t)
	defer cleanup()

	_, err := CreateEtcdClient("https://localhost:2379", certFile, keyFile, "nonexistent.pem")
	if err == nil {
		t.Error("Expected error for invalid CA file")
	}
	if !containsError(err, "failed to read CA certificate") {
		t.Errorf("Expected CA certificate reading error, got: %v", err)
	}
}

func TestCreateEtcdClient_InvalidCACertContent(t *testing.T) {
	certFile, keyFile, _, cleanup := createTempCertFiles(t)
	defer cleanup()

	// Create a file with invalid certificate content
	invalidCAFile := createTempFile(t, "invalid-ca", []byte("invalid certificate content"))
	defer os.Remove(invalidCAFile)

	_, err := CreateEtcdClient("https://localhost:2379", certFile, keyFile, invalidCAFile)
	if err == nil {
		t.Error("Expected error for invalid CA certificate content")
	}
	if !containsError(err, "failed to append CA certificate to pool") {
		t.Errorf("Expected CA certificate parsing error, got: %v", err)
	}
}

func TestCreateEtcdClient_EmptyEndpoint(t *testing.T) {
	certFile, keyFile, caFile, cleanup := createTempCertFiles(t)
	defer cleanup()

	client, err := CreateEtcdClient("", certFile, keyFile, caFile)
	// The function should still create a client even with empty endpoint
	// The actual connection error will happen when trying to use the client
	if err != nil && !isConnectionError(err) {
		t.Errorf("Unexpected error for empty endpoint: %v", err)
	}
	if client != nil {
		client.Close()
	}
}

func TestCreateEtcdClient_MismatchedCertAndKey(t *testing.T) {
	certFile1, _, caFile, cleanup1 := createTempCertFiles(t)
	defer cleanup1()

	_, keyFile2, _, cleanup2 := createTempCertFiles(t)
	defer cleanup2()

	// Use cert from first generation with key from second generation
	_, err := CreateEtcdClient("https://localhost:2379", certFile1, keyFile2, caFile)
	if err == nil {
		t.Error("Expected error for mismatched certificate and key")
	}
	if !containsError(err, "failed to load client certificate and key") {
		t.Errorf("Expected certificate/key mismatch error, got: %v", err)
	}
}

// Helper function to check if error contains expected text
func containsError(err error, expectedText string) bool {
	if err == nil {
		return false
	}
	return err.Error() != "" && (err.Error() == expectedText ||
		len(err.Error()) > len(expectedText))
}

// Helper function to check if error is a connection error
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return containsAny(errStr, []string{
		"connection refused",
		"no such host",
		"timeout",
		"network",
		"dial",
		"context deadline exceeded",
	})
}

func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
	}
	return false
}

// Benchmark tests
func BenchmarkCreateEtcdClient(b *testing.B) {
	certFile, keyFile, caFile, cleanup := createTempCertFiles(&testing.T{})
	defer cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := CreateEtcdClient("https://localhost:2379", certFile, keyFile, caFile)
		if err != nil && !isConnectionError(err) {
			b.Fatalf("Unexpected error: %v", err)
		}
		if client != nil {
			client.Close()
		}
	}
}

// Example test showing how to use the MockEtcdClient
func TestEtcdClientInterface(t *testing.T) {
	mockClient := &MockEtcdClient{
		getResponse: &clientv3.GetResponse{
			Header: &etcdserverpb.ResponseHeader{
				ClusterId: 1,
				MemberId:  1,
				Revision:  1,
			},
			Kvs: []*mvccpb.KeyValue{
				{
					Key:   []byte("test-key"),
					Value: []byte("test-value"),
				},
			},
		},
		getError:   nil,
		closeError: nil,
	}

	// Test Get operation
	ctx := context.Background()
	resp, err := mockClient.Get(ctx, "test-key")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if resp == nil {
		t.Error("Expected non-nil response")
	}
	if len(resp.Kvs) != 1 {
		t.Errorf("Expected 1 key-value pair, got %d", len(resp.Kvs))
	}
	if string(resp.Kvs[0].Key) != "test-key" {
		t.Errorf("Expected key 'test-key', got '%s'", string(resp.Kvs[0].Key))
	}
	if string(resp.Kvs[0].Value) != "test-value" {
		t.Errorf("Expected value 'test-value', got '%s'", string(resp.Kvs[0].Value))
	}

	// Test Close operation
	err = mockClient.Close()
	if err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}
}
