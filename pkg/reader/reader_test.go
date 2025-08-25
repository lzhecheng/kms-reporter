package reader

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	mock_etcd "github.com/lzhecheng/kms-reporter/pkg/etcd/mock"
	mock_reader "github.com/lzhecheng/kms-reporter/pkg/reader/mock"
	mock_recorder "github.com/lzhecheng/kms-reporter/pkg/recorder/mock"
)

// Tests use generated mocks from gomock for all interface dependencies

func TestNewReadOperator(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEtcd := mock_etcd.NewMockEtcdClientOperator(ctrl)
	mockClientset := fake.NewSimpleClientset()
	mockRecorder := mock_recorder.NewMockRecorderOperator(ctrl)
	kmsProviderName := "testprovider"

	reader := NewReadOperator(mockEtcd, mockClientset, mockRecorder, kmsProviderName)

	assert.NotNil(t, reader)
	assert.IsType(t, &ReadOperation{}, reader)

	readOp := reader.(*ReadOperation)
	assert.Equal(t, mockEtcd, readOp.etcdCli)
	assert.Equal(t, mockClientset, readOp.clientset)
	assert.Equal(t, mockRecorder, readOp.RecorderOperator)
	assert.Equal(t, kmsProviderName, readOp.kmsProviderName)
}

func TestReaderOperator_Interface(t *testing.T) {
	// Test using the generated mock for interface-level testing
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockReader := mock_reader.NewMockReaderOperator(ctrl)

	// Setup expectations
	mockReader.EXPECT().
		Read(gomock.Any(), "test-namespace").
		Return(nil).
		Times(1)

	// Test the interface
	var reader ReaderOperator = mockReader
	err := reader.Read(context.Background(), "test-namespace")

	assert.NoError(t, err)
}

func TestReadOperation_Read(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(ctrl *gomock.Controller) (*mock_etcd.MockEtcdClientOperator, *mock_recorder.MockRecorderOperator, kubernetes.Interface)
		namespace     string
		expectedError string
		nilEtcdClient bool
	}{
		{
			name: "successful read with encrypted secrets",
			setup: func(ctrl *gomock.Controller) (*mock_etcd.MockEtcdClientOperator, *mock_recorder.MockRecorderOperator, kubernetes.Interface) {
				etcdMock := mock_etcd.NewMockEtcdClientOperator(ctrl)
				recorderMock := mock_recorder.NewMockRecorderOperator(ctrl)
				clientset := fake.NewSimpleClientset()

				// Setup etcd mock to return encrypted secrets
				kvs := []*mvccpb.KeyValue{
					{
						Key:   []byte("/registry/secrets/default/secret1"),
						Value: []byte("k8s:enc:kms:v2:kmsprovider1:encrypted-data"),
					},
					{
						Key:   []byte("/registry/secrets/default/secret2"),
						Value: []byte("unencrypted-data"),
					},
				}
				etcdMock.EXPECT().Get(gomock.Any(), secretEtcdKey, gomock.Any()).Return(&clientv3.GetResponse{Kvs: kvs}, nil)

				// Setup encryption config ConfigMap
				encryptionConfig := `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- providers:
  - kms:
      apiVersion: v2
      endpoint: unix:///tmp/kms.sock
      name: kmsprovider1
  - identity: {}
  resources:
  - secrets
`
				cm := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      encryptionProviderConfigName,
						Namespace: "test-namespace",
					},
					Data: map[string]string{
						encryptionConfigYAMLKey: encryptionConfig,
					},
				}
				clientset.CoreV1().ConfigMaps("test-namespace").Create(context.TODO(), cm, metav1.CreateOptions{})

				// Setup recorder mock
				recorderMock.EXPECT().Record(gomock.Any(), "test-namespace", []string{"default/secret1"}, []string{"default/secret2"}, false).Return(nil)

				return etcdMock, recorderMock, clientset
			},
			namespace: "test-namespace",
		},
		{
			name: "etcd client is nil",
			setup: func(ctrl *gomock.Controller) (*mock_etcd.MockEtcdClientOperator, *mock_recorder.MockRecorderOperator, kubernetes.Interface) {
				recorderMock := mock_recorder.NewMockRecorderOperator(ctrl)
				clientset := fake.NewSimpleClientset()
				return nil, recorderMock, clientset
			},
			namespace:     "test-namespace",
			expectedError: "etcd client is nil",
			nilEtcdClient: true,
		},
		{
			name: "etcd get fails",
			setup: func(ctrl *gomock.Controller) (*mock_etcd.MockEtcdClientOperator, *mock_recorder.MockRecorderOperator, kubernetes.Interface) {
				etcdMock := mock_etcd.NewMockEtcdClientOperator(ctrl)
				recorderMock := mock_recorder.NewMockRecorderOperator(ctrl)
				clientset := fake.NewSimpleClientset()

				etcdMock.EXPECT().Get(gomock.Any(), secretEtcdKey, gomock.Any()).Return(nil, errors.New("etcd connection failed"))

				return etcdMock, recorderMock, clientset
			},
			namespace:     "test-namespace",
			expectedError: "failed to get key from etcd",
		},
		{
			name: "no secrets found in etcd",
			setup: func(ctrl *gomock.Controller) (*mock_etcd.MockEtcdClientOperator, *mock_recorder.MockRecorderOperator, kubernetes.Interface) {
				etcdMock := mock_etcd.NewMockEtcdClientOperator(ctrl)
				recorderMock := mock_recorder.NewMockRecorderOperator(ctrl)
				clientset := fake.NewSimpleClientset()

				etcdMock.EXPECT().Get(gomock.Any(), secretEtcdKey, gomock.Any()).Return(&clientv3.GetResponse{Kvs: []*mvccpb.KeyValue{}}, nil)

				return etcdMock, recorderMock, clientset
			},
			namespace: "test-namespace",
		},
		{
			name: "encryption config not found",
			setup: func(ctrl *gomock.Controller) (*mock_etcd.MockEtcdClientOperator, *mock_recorder.MockRecorderOperator, kubernetes.Interface) {
				etcdMock := mock_etcd.NewMockEtcdClientOperator(ctrl)
				recorderMock := mock_recorder.NewMockRecorderOperator(ctrl)
				clientset := fake.NewSimpleClientset()

				kvs := []*mvccpb.KeyValue{
					{
						Key:   []byte("/registry/secrets/default/secret1"),
						Value: []byte("k8s:enc:kms:v2:kmsprovider1:encrypted-data"),
					},
				}
				etcdMock.EXPECT().Get(gomock.Any(), secretEtcdKey, gomock.Any()).Return(&clientv3.GetResponse{Kvs: kvs}, nil)
				// ConfigMap not created, so it won't be found

				return etcdMock, recorderMock, clientset
			},
			namespace:     "test-namespace",
			expectedError: "failed to get latest provider seq",
		},
		{
			name: "recorder fails",
			setup: func(ctrl *gomock.Controller) (*mock_etcd.MockEtcdClientOperator, *mock_recorder.MockRecorderOperator, kubernetes.Interface) {
				etcdMock := mock_etcd.NewMockEtcdClientOperator(ctrl)
				recorderMock := mock_recorder.NewMockRecorderOperator(ctrl)
				clientset := fake.NewSimpleClientset()

				kvs := []*mvccpb.KeyValue{
					{
						Key:   []byte("/registry/secrets/default/secret1"),
						Value: []byte("k8s:enc:kms:v2:kmsprovider1:encrypted-data"),
					},
				}
				etcdMock.EXPECT().Get(gomock.Any(), secretEtcdKey, gomock.Any()).Return(&clientv3.GetResponse{Kvs: kvs}, nil)

				encryptionConfig := `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- providers:
  - kms:
      apiVersion: v2
      endpoint: unix:///tmp/kms.sock
      name: kmsprovider1
  - identity: {}
  resources:
  - secrets
`
				cm := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      encryptionProviderConfigName,
						Namespace: "test-namespace",
					},
					Data: map[string]string{
						encryptionConfigYAMLKey: encryptionConfig,
					},
				}
				clientset.CoreV1().ConfigMaps("test-namespace").Create(context.TODO(), cm, metav1.CreateOptions{})

				recorderMock.EXPECT().Record(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("recorder failed"))

				return etcdMock, recorderMock, clientset
			},
			namespace:     "test-namespace",
			expectedError: "failed to store secret encryption status in recorder",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			etcdMock, recorderMock, clientset := tt.setup(ctrl)

			var readOp *ReadOperation
			if tt.nilEtcdClient {
				readOp = &ReadOperation{
					etcdCli:          nil,
					clientset:        clientset,
					RecorderOperator: recorderMock,
					kmsProviderName:  "kmsprovider",
				}
			} else {
				readOp = &ReadOperation{
					etcdCli:          etcdMock,
					clientset:        clientset,
					RecorderOperator: recorderMock,
					kmsProviderName:  "kmsprovider",
				}
			}

			err := readOp.Read(context.Background(), tt.namespace)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReadOperation_analyzeSecretEncryption(t *testing.T) {
	tests := []struct {
		name                         string
		kvs                          []*mvccpb.KeyValue
		latestProviderSeq            int
		expectedEncryptedSecrets     []string
		expectedUnencryptedSecrets   []string
		expectedAllUseLatestProvider bool
	}{
		{
			name: "mixed encrypted and unencrypted secrets with latest provider",
			kvs: []*mvccpb.KeyValue{
				{
					Key:   []byte("/registry/secrets/default/secret1"),
					Value: []byte("k8s:enc:kms:v2:kmsprovider1:encrypted-data"),
				},
				{
					Key:   []byte("/registry/secrets/kube-system/secret2"),
					Value: []byte("unencrypted-data"),
				},
				{
					Key:   []byte("/registry/secrets/default/secret3"),
					Value: []byte("k8s:enc:kms:v2:kmsprovider1:more-encrypted-data"),
				},
			},
			latestProviderSeq:            1,
			expectedEncryptedSecrets:     []string{"default/secret1", "default/secret3"},
			expectedUnencryptedSecrets:   []string{"kube-system/secret2"},
			expectedAllUseLatestProvider: false, // because secret2 is unencrypted (seq 0 != 1)
		},
		{
			name: "all secrets encrypted with latest provider",
			kvs: []*mvccpb.KeyValue{
				{
					Key:   []byte("/registry/secrets/default/secret1"),
					Value: []byte("k8s:enc:kms:v2:kmsprovider2:encrypted-data"),
				},
				{
					Key:   []byte("/registry/secrets/default/secret2"),
					Value: []byte("k8s:enc:kms:v2:kmsprovider2:more-encrypted-data"),
				},
			},
			latestProviderSeq:            2,
			expectedEncryptedSecrets:     []string{"default/secret1", "default/secret2"},
			expectedUnencryptedSecrets:   []string{},
			expectedAllUseLatestProvider: true,
		},
		{
			name: "encrypted secrets with older provider",
			kvs: []*mvccpb.KeyValue{
				{
					Key:   []byte("/registry/secrets/default/secret1"),
					Value: []byte("k8s:enc:kms:v2:kmsprovider1:encrypted-data"),
				},
			},
			latestProviderSeq:            2,
			expectedEncryptedSecrets:     []string{"default/secret1"},
			expectedUnencryptedSecrets:   []string{},
			expectedAllUseLatestProvider: false, // seq 1 != 2
		},
		{
			name:                         "no secrets",
			kvs:                          []*mvccpb.KeyValue{},
			latestProviderSeq:            1,
			expectedEncryptedSecrets:     []string{},
			expectedUnencryptedSecrets:   []string{},
			expectedAllUseLatestProvider: true,
		},
		{
			name: "invalid key format - should be skipped",
			kvs: []*mvccpb.KeyValue{
				{
					Key:   []byte("/invalid/key"),
					Value: []byte("some-data"),
				},
				{
					Key:   []byte("/registry/secrets/default/valid-secret"),
					Value: []byte("unencrypted-data"),
				},
			},
			latestProviderSeq:            1,
			expectedEncryptedSecrets:     []string{},
			expectedUnencryptedSecrets:   []string{"default/valid-secret"},
			expectedAllUseLatestProvider: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readOp := &ReadOperation{
				kmsProviderName: "kmsprovider",
			}
			result := readOp.analyzeSecretEncryption(tt.kvs, tt.latestProviderSeq)

			assert.Equal(t, tt.expectedEncryptedSecrets, result.EncryptedSecrets)
			assert.Equal(t, tt.expectedUnencryptedSecrets, result.UnencryptedSecrets)
			assert.Equal(t, tt.expectedAllUseLatestProvider, result.AllSecretsUseLatestProvider)
		})
	}
}

func TestReadOperation_getLatestProviderSeq(t *testing.T) {
	tests := []struct {
		name           string
		setupConfigMap func(kubernetes.Interface, string)
		namespace      string
		expectedSeq    int
		expectedError  string
	}{
		{
			name: "valid encryption config with KMS provider",
			setupConfigMap: func(clientset kubernetes.Interface, namespace string) {
				encryptionConfig := `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- providers:
  - kms:
      apiVersion: v2
      endpoint: unix:///tmp/kms.sock
      name: kmsprovider3
  - identity: {}
  resources:
  - secrets
`
				cm := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      encryptionProviderConfigName,
						Namespace: namespace,
					},
					Data: map[string]string{
						encryptionConfigYAMLKey: encryptionConfig,
					},
				}
				clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), cm, metav1.CreateOptions{})
			},
			namespace:   "test-namespace",
			expectedSeq: 3,
		},
		{
			name: "encryption config with multiple providers - returns first KMS",
			setupConfigMap: func(clientset kubernetes.Interface, namespace string) {
				encryptionConfig := `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- providers:
  - identity: {}
  - kms:
      apiVersion: v2
      endpoint: unix:///tmp/kms.sock
      name: kmsprovider5
  - kms:
      apiVersion: v2
      endpoint: unix:///tmp/kms2.sock
      name: kmsprovider7
  resources:
  - secrets
`
				cm := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      encryptionProviderConfigName,
						Namespace: namespace,
					},
					Data: map[string]string{
						encryptionConfigYAMLKey: encryptionConfig,
					},
				}
				clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), cm, metav1.CreateOptions{})
			},
			namespace:   "test-namespace",
			expectedSeq: 5,
		},
		{
			name: "encryption config with only identity provider",
			setupConfigMap: func(clientset kubernetes.Interface, namespace string) {
				encryptionConfig := `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- providers:
  - identity: {}
  resources:
  - secrets
`
				cm := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      encryptionProviderConfigName,
						Namespace: namespace,
					},
					Data: map[string]string{
						encryptionConfigYAMLKey: encryptionConfig,
					},
				}
				clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), cm, metav1.CreateOptions{})
			},
			namespace:   "test-namespace",
			expectedSeq: identityProviderSeq,
		},
		{
			name: "configmap not found",
			setupConfigMap: func(clientset kubernetes.Interface, namespace string) {
				// Don't create the ConfigMap
			},
			namespace:     "test-namespace",
			expectedError: "failed to get encryption-provider-config ConfigMap",
		},
		{
			name: "encryption config yaml key missing",
			setupConfigMap: func(clientset kubernetes.Interface, namespace string) {
				cm := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      encryptionProviderConfigName,
						Namespace: namespace,
					},
					Data: map[string]string{
						"wrong-key": "some-config",
					},
				}
				clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), cm, metav1.CreateOptions{})
			},
			namespace:     "test-namespace",
			expectedError: "encryption-provider-config.yaml not found in ConfigMap data",
		},
		{
			name: "invalid yaml in config",
			setupConfigMap: func(clientset kubernetes.Interface, namespace string) {
				cm := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      encryptionProviderConfigName,
						Namespace: namespace,
					},
					Data: map[string]string{
						encryptionConfigYAMLKey: "invalid: yaml: content: [",
					},
				}
				clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), cm, metav1.CreateOptions{})
			},
			namespace:     "test-namespace",
			expectedError: "failed to unmarshal encryption configuration",
		},
		{
			name: "KMS provider with invalid name format",
			setupConfigMap: func(clientset kubernetes.Interface, namespace string) {
				encryptionConfig := `
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- providers:
  - kms:
      apiVersion: v2
      endpoint: unix:///tmp/kms.sock
      name: invalidname
  - identity: {}
  resources:
  - secrets
`
				cm := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      encryptionProviderConfigName,
						Namespace: namespace,
					},
					Data: map[string]string{
						encryptionConfigYAMLKey: encryptionConfig,
					},
				}
				clientset.CoreV1().ConfigMaps(namespace).Create(context.TODO(), cm, metav1.CreateOptions{})
			},
			namespace:   "test-namespace",
			expectedSeq: identityProviderSeq, // Should return identity provider seq when no valid KMS found
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			tt.setupConfigMap(clientset, tt.namespace)

			readOp := &ReadOperation{
				clientset:       clientset,
				kmsProviderName: "kmsprovider",
			}

			seq, err := readOp.getLatestProviderSeq(context.Background(), tt.namespace)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSeq, seq)
			}
		})
	}
}
