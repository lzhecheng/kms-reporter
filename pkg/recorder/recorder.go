package recorder

import (
	"context"
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	klog "k8s.io/klog/v2"
)

const (
	// ConfigMap name used to store KMS encryption status reports
	kmsReporterConfigMapName = "kms-reporter"

	// Special pattern indicating all secrets belong to this category
	allSecretsPattern = "ALL_SECRETS"

	// ConfigMap data keys for storing encryption status information
	encryptedSecretsKey          = "ENCRYPTED"
	unencryptedSecretsKey        = "UNENCRYPTED"
	encryptedByLatestProviderKey = "ENCRYPTED_BY_LATEST_SEQ"
)

// formatSecretLists converts secret lists into string representations for ConfigMap storage.
// Returns formatted strings for encrypted and unencrypted secret lists, using a special
// pattern when all secrets belong to one category.
func formatSecretLists(encryptedSecrets, unencryptedSecrets []string) (string, string) {
	var encryptedValue, unencryptedValue string

	hasEncrypted := len(encryptedSecrets) > 0
	hasUnencrypted := len(unencryptedSecrets) > 0

	switch {
	case hasEncrypted && hasUnencrypted:
		// Mixed case: some encrypted, some unencrypted
		encryptedValue = strings.Join(encryptedSecrets, ",")
		unencryptedValue = strings.Join(unencryptedSecrets, ",")
	case !hasEncrypted && hasUnencrypted:
		// All secrets are unencrypted
		unencryptedValue = allSecretsPattern
	case hasEncrypted && !hasUnencrypted:
		// All secrets are encrypted
		encryptedValue = allSecretsPattern
	default:
		// No secrets found - this shouldn't happen in normal operation
		klog.Warning("No secrets found to record")
		return "", ""
	}

	return encryptedValue, unencryptedValue
}

// RecorderOperator defines the interface for recording secret encryption status reports.
// It stores the analysis results in a Kubernetes ConfigMap for monitoring and alerting purposes.
type RecorderOperator interface {
	Record(ctx context.Context, namespace string, encryptedSecrets, unencryptedSecrets []string, allSecretsUseLatestProvider bool) error
}

// RecorderOperation handles the storage of secret encryption status reports in Kubernetes ConfigMaps.
type RecorderOperation struct {
	Clientset kubernetes.Interface
}

func NewRecorderOperator(clientset kubernetes.Interface) RecorderOperator {
	return &RecorderOperation{
		Clientset: clientset,
	}
}

// Record stores the secret encryption status analysis results in a Kubernetes ConfigMap.
// It creates a new ConfigMap if one doesn't exist, or updates an existing one.
func (o *RecorderOperation) Record(ctx context.Context, namespace string, encryptedSecrets, unencryptedSecrets []string, allSecretsUseLatestProvider bool) error {
	allSecretsEncrypted := len(unencryptedSecrets) == 0

	encryptedValue, unencryptedValue := formatSecretLists(encryptedSecrets, unencryptedSecrets)

	configMap, err := o.Clientset.CoreV1().ConfigMaps(namespace).Get(ctx, kmsReporterConfigMapName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get ConfigMap: %w", err)
		}

		// ConfigMap doesn't exist, create a new one
		return o.createConfigMap(ctx, namespace, encryptedValue, unencryptedValue, allSecretsEncrypted, allSecretsUseLatestProvider)
	}

	// ConfigMap exists, update it
	return o.updateConfigMap(ctx, configMap, encryptedValue, unencryptedValue, allSecretsEncrypted, allSecretsUseLatestProvider)
}

// createConfigMap creates a new ConfigMap with the encryption status data.
func (o *RecorderOperation) createConfigMap(ctx context.Context, namespace, encryptedValue, unencryptedValue string, allSecretsEncrypted, allSecretsUseLatestProvider bool) error {
	configMap := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kmsReporterConfigMapName,
			Namespace: namespace,
		},
		Data: map[string]string{
			encryptedSecretsKey:   encryptedValue,
			unencryptedSecretsKey: unencryptedValue,
		},
	}

	// Only add the latest provider status if all secrets are encrypted
	if allSecretsEncrypted {
		configMap.Data[encryptedByLatestProviderKey] = fmt.Sprintf("%t", allSecretsUseLatestProvider)
	}

	if _, err := o.Clientset.CoreV1().ConfigMaps(namespace).Create(ctx, configMap, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("failed to create ConfigMap: %w", err)
	}

	klog.Infof("ConfigMap %s created successfully", kmsReporterConfigMapName)
	return nil
}

// updateConfigMap updates an existing ConfigMap with new encryption status data.
func (o *RecorderOperation) updateConfigMap(ctx context.Context, configMap *v1.ConfigMap, encryptedValue, unencryptedValue string, allSecretsEncrypted, allSecretsUseLatestProvider bool) error {
	configMap.Data[encryptedSecretsKey] = encryptedValue
	configMap.Data[unencryptedSecretsKey] = unencryptedValue

	// Only add/update the latest provider status if all secrets are encrypted
	if allSecretsEncrypted {
		configMap.Data[encryptedByLatestProviderKey] = fmt.Sprintf("%t", allSecretsUseLatestProvider)
	} else {
		// Remove the key if not all secrets are encrypted
		delete(configMap.Data, encryptedByLatestProviderKey)
	}

	if _, err := o.Clientset.CoreV1().ConfigMaps(configMap.Namespace).Update(ctx, configMap, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update ConfigMap: %w", err)
	}

	klog.Infof("ConfigMap %s updated successfully", kmsReporterConfigMapName)
	return nil
}
