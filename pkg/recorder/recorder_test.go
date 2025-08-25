package recorder

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	mock_recorder "github.com/lzhecheng/kms-reporter/pkg/recorder/mock"
)

func TestFormatSecretLists(t *testing.T) {
	tests := []struct {
		name                     string
		encryptedSecrets         []string
		unencryptedSecrets       []string
		expectedEncryptedValue   string
		expectedUnencryptedValue string
	}{
		{
			name:                     "mixed encrypted and unencrypted secrets",
			encryptedSecrets:         []string{"default/secret1", "kube-system/secret2"},
			unencryptedSecrets:       []string{"default/secret3", "kube-system/secret4"},
			expectedEncryptedValue:   "default/secret1,kube-system/secret2",
			expectedUnencryptedValue: "default/secret3,kube-system/secret4",
		},
		{
			name:                     "all secrets encrypted",
			encryptedSecrets:         []string{"default/secret1", "kube-system/secret2"},
			unencryptedSecrets:       []string{},
			expectedEncryptedValue:   allSecretsPattern,
			expectedUnencryptedValue: "",
		},
		{
			name:                     "all secrets unencrypted",
			encryptedSecrets:         []string{},
			unencryptedSecrets:       []string{"default/secret1", "kube-system/secret2"},
			expectedEncryptedValue:   "",
			expectedUnencryptedValue: allSecretsPattern,
		},
		{
			name:                     "no secrets - edge case",
			encryptedSecrets:         []string{},
			unencryptedSecrets:       []string{},
			expectedEncryptedValue:   "",
			expectedUnencryptedValue: "",
		},
		{
			name:                     "single encrypted secret",
			encryptedSecrets:         []string{"default/secret1"},
			unencryptedSecrets:       []string{},
			expectedEncryptedValue:   allSecretsPattern,
			expectedUnencryptedValue: "",
		},
		{
			name:                     "single unencrypted secret",
			encryptedSecrets:         []string{},
			unencryptedSecrets:       []string{"default/secret1"},
			expectedEncryptedValue:   "",
			expectedUnencryptedValue: allSecretsPattern,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptedValue, unencryptedValue := formatSecretLists(tt.encryptedSecrets, tt.unencryptedSecrets)
			assert.Equal(t, tt.expectedEncryptedValue, encryptedValue)
			assert.Equal(t, tt.expectedUnencryptedValue, unencryptedValue)
		})
	}
}

func TestNewRecorderOperator(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	recorder := NewRecorderOperator(clientset)

	assert.NotNil(t, recorder)
	assert.IsType(t, &RecorderOperation{}, recorder)

	recorderOp := recorder.(*RecorderOperation)
	assert.Equal(t, clientset, recorderOp.Clientset)
}

func TestRecorderOperation_Record(t *testing.T) {
	tests := []struct {
		name                        string
		setup                       func(*fake.Clientset)
		namespace                   string
		encryptedSecrets            []string
		unencryptedSecrets          []string
		allSecretsUseLatestProvider bool
		expectedError               string
		validateConfigMap           func(*testing.T, *fake.Clientset, string)
	}{
		{
			name: "create new configmap - all secrets encrypted with latest provider",
			setup: func(clientset *fake.Clientset) {
				// No existing ConfigMap, so Get will return NotFound error
			},
			namespace:                   "test-namespace",
			encryptedSecrets:            []string{"default/secret1", "kube-system/secret2"},
			unencryptedSecrets:          []string{},
			allSecretsUseLatestProvider: true,
			validateConfigMap: func(t *testing.T, clientset *fake.Clientset, namespace string) {
				cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), kmsReporterConfigMapName, metav1.GetOptions{})
				assert.NoError(t, err)
				assert.Equal(t, allSecretsPattern, cm.Data[encryptedSecretsKey])
				assert.Equal(t, "", cm.Data[unencryptedSecretsKey])
				assert.Equal(t, "true", cm.Data[encryptedByLatestProviderKey])
			},
		},
		{
			name: "create new configmap - mixed secrets",
			setup: func(clientset *fake.Clientset) {
				// No existing ConfigMap
			},
			namespace:                   "test-namespace",
			encryptedSecrets:            []string{"default/secret1"},
			unencryptedSecrets:          []string{"default/secret2"},
			allSecretsUseLatestProvider: false,
			validateConfigMap: func(t *testing.T, clientset *fake.Clientset, namespace string) {
				cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), kmsReporterConfigMapName, metav1.GetOptions{})
				assert.NoError(t, err)
				assert.Equal(t, "default/secret1", cm.Data[encryptedSecretsKey])
				assert.Equal(t, "default/secret2", cm.Data[unencryptedSecretsKey])
				_, exists := cm.Data[encryptedByLatestProviderKey]
				assert.False(t, exists, "encrypted by latest provider key should not exist when not all secrets are encrypted")
			},
		},
		{
			name: "update existing configmap - all secrets encrypted with latest provider",
			setup: func(clientset *fake.Clientset) {
				// Create existing ConfigMap
				existingCM := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      kmsReporterConfigMapName,
						Namespace: "test-namespace",
					},
					Data: map[string]string{
						encryptedSecretsKey:   "old-encrypted-value",
						unencryptedSecretsKey: "old-unencrypted-value",
					},
				}
				clientset.CoreV1().ConfigMaps("test-namespace").Create(context.TODO(), existingCM, metav1.CreateOptions{})
			},
			namespace:                   "test-namespace",
			encryptedSecrets:            []string{"default/new-secret1", "default/new-secret2"},
			unencryptedSecrets:          []string{},
			allSecretsUseLatestProvider: true,
			validateConfigMap: func(t *testing.T, clientset *fake.Clientset, namespace string) {
				cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), kmsReporterConfigMapName, metav1.GetOptions{})
				assert.NoError(t, err)
				assert.Equal(t, allSecretsPattern, cm.Data[encryptedSecretsKey])
				assert.Equal(t, "", cm.Data[unencryptedSecretsKey])
				assert.Equal(t, "true", cm.Data[encryptedByLatestProviderKey])
			},
		},
		{
			name: "update existing configmap - remove latest provider key when not all encrypted",
			setup: func(clientset *fake.Clientset) {
				// Create existing ConfigMap with latest provider key
				existingCM := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      kmsReporterConfigMapName,
						Namespace: "test-namespace",
					},
					Data: map[string]string{
						encryptedSecretsKey:          "old-encrypted-value",
						unencryptedSecretsKey:        "",
						encryptedByLatestProviderKey: "true",
					},
				}
				clientset.CoreV1().ConfigMaps("test-namespace").Create(context.TODO(), existingCM, metav1.CreateOptions{})
			},
			namespace:                   "test-namespace",
			encryptedSecrets:            []string{"default/secret1"},
			unencryptedSecrets:          []string{"default/secret2"},
			allSecretsUseLatestProvider: false,
			validateConfigMap: func(t *testing.T, clientset *fake.Clientset, namespace string) {
				cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), kmsReporterConfigMapName, metav1.GetOptions{})
				assert.NoError(t, err)
				assert.Equal(t, "default/secret1", cm.Data[encryptedSecretsKey])
				assert.Equal(t, "default/secret2", cm.Data[unencryptedSecretsKey])
				_, exists := cm.Data[encryptedByLatestProviderKey]
				assert.False(t, exists, "encrypted by latest provider key should be removed when not all secrets are encrypted")
			},
		},
		{
			name: "all secrets unencrypted",
			setup: func(clientset *fake.Clientset) {
				// No existing ConfigMap
			},
			namespace:                   "test-namespace",
			encryptedSecrets:            []string{},
			unencryptedSecrets:          []string{"default/secret1", "default/secret2"},
			allSecretsUseLatestProvider: false,
			validateConfigMap: func(t *testing.T, clientset *fake.Clientset, namespace string) {
				cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), kmsReporterConfigMapName, metav1.GetOptions{})
				assert.NoError(t, err)
				assert.Equal(t, "", cm.Data[encryptedSecretsKey])
				assert.Equal(t, allSecretsPattern, cm.Data[unencryptedSecretsKey])
				_, exists := cm.Data[encryptedByLatestProviderKey]
				assert.False(t, exists, "encrypted by latest provider key should not exist when no secrets are encrypted")
			},
		},
		{
			name: "error getting configmap (not NotFound error)",
			setup: func(clientset *fake.Clientset) {
				// Simulate a different error than NotFound
				clientset.PrependReactor("get", "configmaps", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, errors.New("internal server error")
				})
			},
			namespace:                   "test-namespace",
			encryptedSecrets:            []string{"default/secret1"},
			unencryptedSecrets:          []string{},
			allSecretsUseLatestProvider: true,
			expectedError:               "failed to get ConfigMap",
		},
		{
			name: "error creating configmap",
			setup: func(clientset *fake.Clientset) {
				// Simulate create error
				clientset.PrependReactor("create", "configmaps", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, errors.New("failed to create")
				})
			},
			namespace:                   "test-namespace",
			encryptedSecrets:            []string{"default/secret1"},
			unencryptedSecrets:          []string{},
			allSecretsUseLatestProvider: true,
			expectedError:               "failed to create ConfigMap",
		},
		{
			name: "error updating configmap",
			setup: func(clientset *fake.Clientset) {
				// Create existing ConfigMap
				existingCM := &v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      kmsReporterConfigMapName,
						Namespace: "test-namespace",
					},
					Data: map[string]string{
						encryptedSecretsKey:   "old-value",
						unencryptedSecretsKey: "",
					},
				}
				clientset.CoreV1().ConfigMaps("test-namespace").Create(context.TODO(), existingCM, metav1.CreateOptions{})

				// Simulate update error
				clientset.PrependReactor("update", "configmaps", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, nil, errors.New("failed to update")
				})
			},
			namespace:                   "test-namespace",
			encryptedSecrets:            []string{"default/secret1"},
			unencryptedSecrets:          []string{},
			allSecretsUseLatestProvider: true,
			expectedError:               "failed to update ConfigMap",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			tt.setup(clientset)

			recorder := &RecorderOperation{
				Clientset: clientset,
			}

			err := recorder.Record(context.Background(), tt.namespace, tt.encryptedSecrets, tt.unencryptedSecrets, tt.allSecretsUseLatestProvider)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				if tt.validateConfigMap != nil {
					tt.validateConfigMap(t, clientset, tt.namespace)
				}
			}
		})
	}
}

func TestRecorderOperation_Record_Integration(t *testing.T) {
	// Integration test that tests the complete flow
	clientset := fake.NewSimpleClientset()
	recorder := NewRecorderOperator(clientset)

	namespace := "integration-test"
	encryptedSecrets := []string{"default/secret1", "kube-system/secret2"}
	unencryptedSecrets := []string{"default/secret3"}

	// First call - creates ConfigMap
	err := recorder.Record(context.Background(), namespace, encryptedSecrets, unencryptedSecrets, false)
	assert.NoError(t, err)

	// Verify ConfigMap was created
	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), kmsReporterConfigMapName, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "default/secret1,kube-system/secret2", cm.Data[encryptedSecretsKey])
	assert.Equal(t, "default/secret3", cm.Data[unencryptedSecretsKey])
	_, exists := cm.Data[encryptedByLatestProviderKey]
	assert.False(t, exists, "latest provider key should not exist when not all secrets are encrypted")

	// Second call - updates ConfigMap (all secrets now encrypted)
	allEncryptedSecrets := []string{"default/secret1", "kube-system/secret2", "default/secret3"}
	err = recorder.Record(context.Background(), namespace, allEncryptedSecrets, []string{}, true)
	assert.NoError(t, err)

	// Verify ConfigMap was updated
	cm, err = clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), kmsReporterConfigMapName, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, allSecretsPattern, cm.Data[encryptedSecretsKey])
	assert.Equal(t, "", cm.Data[unencryptedSecretsKey])
	assert.Equal(t, "true", cm.Data[encryptedByLatestProviderKey])

	// Third call - updates ConfigMap (some secrets become unencrypted again)
	err = recorder.Record(context.Background(), namespace, []string{"default/secret1"}, []string{"default/secret2"}, false)
	assert.NoError(t, err)

	// Verify ConfigMap was updated and latest provider key was removed
	cm, err = clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), kmsReporterConfigMapName, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, "default/secret1", cm.Data[encryptedSecretsKey])
	assert.Equal(t, "default/secret2", cm.Data[unencryptedSecretsKey])
	_, exists = cm.Data[encryptedByLatestProviderKey]
	assert.False(t, exists, "latest provider key should be removed when not all secrets are encrypted")
}

func TestRecorderOperation_CreateConfigMap_EdgeCases(t *testing.T) {
	tests := []struct {
		name                        string
		encryptedSecrets            []string
		unencryptedSecrets          []string
		allSecretsUseLatestProvider bool
		expectedEncryptedValue      string
		expectedUnencryptedValue    string
		shouldHaveLatestProviderKey bool
		expectedLatestProviderValue string
	}{
		{
			name:                        "all encrypted with latest provider true",
			encryptedSecrets:            []string{"default/secret1"},
			unencryptedSecrets:          []string{},
			allSecretsUseLatestProvider: true,
			expectedEncryptedValue:      allSecretsPattern,
			expectedUnencryptedValue:    "",
			shouldHaveLatestProviderKey: true,
			expectedLatestProviderValue: "true",
		},
		{
			name:                        "all encrypted with latest provider false",
			encryptedSecrets:            []string{"default/secret1"},
			unencryptedSecrets:          []string{},
			allSecretsUseLatestProvider: false,
			expectedEncryptedValue:      allSecretsPattern,
			expectedUnencryptedValue:    "",
			shouldHaveLatestProviderKey: true,
			expectedLatestProviderValue: "false",
		},
		{
			name:                        "mixed secrets - latest provider key should not exist",
			encryptedSecrets:            []string{"default/secret1"},
			unencryptedSecrets:          []string{"default/secret2"},
			allSecretsUseLatestProvider: true, // This should be ignored when not all secrets are encrypted
			expectedEncryptedValue:      "default/secret1",
			expectedUnencryptedValue:    "default/secret2",
			shouldHaveLatestProviderKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			recorder := &RecorderOperation{
				Clientset: clientset,
			}

			err := recorder.Record(context.Background(), "test-namespace", tt.encryptedSecrets, tt.unencryptedSecrets, tt.allSecretsUseLatestProvider)
			assert.NoError(t, err)

			// Verify the ConfigMap contents
			cm, err := clientset.CoreV1().ConfigMaps("test-namespace").Get(context.TODO(), kmsReporterConfigMapName, metav1.GetOptions{})
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedEncryptedValue, cm.Data[encryptedSecretsKey])
			assert.Equal(t, tt.expectedUnencryptedValue, cm.Data[unencryptedSecretsKey])

			if tt.shouldHaveLatestProviderKey {
				value, exists := cm.Data[encryptedByLatestProviderKey]
				assert.True(t, exists, "latest provider key should exist")
				assert.Equal(t, tt.expectedLatestProviderValue, value)
			} else {
				_, exists := cm.Data[encryptedByLatestProviderKey]
				assert.False(t, exists, "latest provider key should not exist")
			}
		})
	}
}

func TestRecorderOperator_Interface(t *testing.T) {
	// Test using the generated mock for interface-level testing
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRecorder := mock_recorder.NewMockRecorderOperator(ctrl)

	// Setup expectations
	mockRecorder.EXPECT().
		Record(gomock.Any(), "test-namespace", []string{"secret1"}, []string{"secret2"}, false).
		Return(nil).
		Times(1)

	// Test the interface
	var recorder RecorderOperator = mockRecorder
	err := recorder.Record(context.Background(), "test-namespace", []string{"secret1"}, []string{"secret2"}, false)

	assert.NoError(t, err)
}

func TestRecorderOperator_Interface_WithError(t *testing.T) {
	// Test error case using the generated mock
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRecorder := mock_recorder.NewMockRecorderOperator(ctrl)

	// Setup expectations for error case
	mockRecorder.EXPECT().
		Record(gomock.Any(), "test-namespace", gomock.Any(), gomock.Any(), gomock.Any()).
		Return(errors.New("mock recorder error")).
		Times(1)

	// Test the interface
	var recorder RecorderOperator = mockRecorder
	err := recorder.Record(context.Background(), "test-namespace", []string{"secret1"}, []string{}, true)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock recorder error")
}
