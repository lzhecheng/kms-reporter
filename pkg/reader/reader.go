package reader

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"

	"github.com/lzhecheng/kms-reporter/pkg/etcd"
	"github.com/lzhecheng/kms-reporter/pkg/recorder"
	"github.com/lzhecheng/kms-reporter/pkg/utils"
)

const (
	secretEtcdKey                = "/registry/secrets"
	defaultTimeout               = 5 * time.Second
	encryptionProviderConfigName = "encryption-provider-config"
	encryptionConfigYAMLKey      = "encryption-provider-config.yaml"
	identityProviderSeq          = -1 // Sequence number for identity (no encryption) provider
)

// ReaderOperator defines the interface for reading and analyzing secret encryption status from etcd.
type ReaderOperator interface {
	Read(ctx context.Context, namespace string) error
}

// ReadOperation handles the analysis of secret encryption status by reading from etcd
// and comparing against the current KMS provider configuration.
type ReadOperation struct {
	etcdCli   etcd.EtcdClientOperator
	clientset kubernetes.Interface
	recorder.RecorderOperator
	kmsProviderName string
}

func NewReadOperator(etcdCli etcd.EtcdClientOperator, clientset kubernetes.Interface, recorderOperator recorder.RecorderOperator, kmsProviderName string) ReaderOperator {
	return &ReadOperation{
		etcdCli:          etcdCli,
		clientset:        clientset,
		RecorderOperator: recorderOperator,
		kmsProviderName:  kmsProviderName,
	}
}

// Read analyzes the encryption status of secrets stored in etcd by comparing
// their encryption sequence numbers against the latest KMS provider configuration.
func (o *ReadOperation) Read(ctx context.Context, namespace string) error {
	// Get the secret
	etcdCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	if o.etcdCli == nil {
		return fmt.Errorf("etcd client is nil")
	}
	// TODO: Pagination for perf
	resp, err := o.etcdCli.Get(etcdCtx, secretEtcdKey, clientv3.WithPrefix())
	if err != nil {
		return fmt.Errorf("failed to get key from etcd: %w", err)
	}

	if len(resp.Kvs) == 0 {
		klog.Warning("No secrets found in etcd")
		return nil
	}

	latestProviderSeq, err := o.getLatestProviderSeq(ctx, namespace)
	if err != nil {
		return fmt.Errorf("failed to get latest provider seq: %w", err)
	}

	analysisResult := o.analyzeSecretEncryption(resp.Kvs, latestProviderSeq)

	if err := o.RecorderOperator.Record(ctx, namespace, analysisResult.EncryptedSecrets, analysisResult.UnencryptedSecrets, analysisResult.AllSecretsUseLatestProvider); err != nil {
		return fmt.Errorf("failed to store secret encryption status in recorder: %w", err)
	}
	klog.Info("Read etcd successfully")
	return nil
}

// analyzeSecretEncryption processes etcd key-value pairs to categorize secrets by encryption status
// and determines if all secrets use the latest provider sequence.
func (o *ReadOperation) analyzeSecretEncryption(kvs []*mvccpb.KeyValue, latestProviderSeq int) EncryptionAnalysisResult {
	result := EncryptionAnalysisResult{
		EncryptedSecrets:            []string{},
		UnencryptedSecrets:          []string{},
		AllSecretsUseLatestProvider: true,
	}

	for _, kv := range kvs {
		key := string(kv.Key)
		value := string(kv.Value)

		encrypted, parsedSecret, providerSeq, err := utils.ParseEtcdObject(key, value, o.kmsProviderName)
		if err != nil {
			klog.ErrorS(err, "Failed to parse secret")
			continue
		}

		if providerSeq != latestProviderSeq {
			result.AllSecretsUseLatestProvider = false
		}

		if encrypted {
			result.EncryptedSecrets = append(result.EncryptedSecrets, parsedSecret)
		} else {
			result.UnencryptedSecrets = append(result.UnencryptedSecrets, parsedSecret)
		}
	}

	return result
}

// getLatestProviderSeq returns the sequence number of the first KMS provider found in the encryption configuration.
// If no KMS provider is found, it returns identityProviderSeq (-1) indicating identity (no encryption) provider.
func (o *ReadOperation) getLatestProviderSeq(ctx context.Context, namespace string) (int, error) {
	k8sCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	// Get the encryption-provider-config ConfigMap
	cm, err := o.clientset.CoreV1().ConfigMaps(namespace).Get(k8sCtx, encryptionProviderConfigName, metav1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to get encryption-provider-config ConfigMap: %w", err)
	}

	// Get the encryption configuration YAML from the ConfigMap
	encryptionConfigYAML, exists := cm.Data[encryptionConfigYAMLKey]
	if !exists {
		return 0, fmt.Errorf("%s not found in ConfigMap data", encryptionConfigYAMLKey)
	}

	// Parse the YAML into our configuration structure
	var encryptionConfig EncryptionConfiguration
	if err := yaml.Unmarshal([]byte(encryptionConfigYAML), &encryptionConfig); err != nil {
		return 0, fmt.Errorf("failed to unmarshal encryption configuration: %w", err)
	}

	// Find the first KMS provider sequence number
	providerNameRegex := regexp.MustCompile(o.kmsProviderName + `(\d+)`)

	for _, resource := range encryptionConfig.Resources {
		for _, provider := range resource.Providers {
			if provider.KMS != nil {
				matches := providerNameRegex.FindStringSubmatch(provider.KMS.Name)
				if len(matches) == 2 {
					providerSeq, err := strconv.Atoi(matches[1])
					if err != nil {
						klog.ErrorS(err, "Failed to parse provider sequence number", "providerName", provider.KMS.Name)
						continue
					}
					return providerSeq, nil
				}
			}
		}
	}

	return identityProviderSeq, nil
}
