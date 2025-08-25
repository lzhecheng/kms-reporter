package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	klog "k8s.io/klog/v2"

	"github.com/lzhecheng/kms-reporter/pkg/etcd"
	"github.com/lzhecheng/kms-reporter/pkg/reader"
	"github.com/lzhecheng/kms-reporter/pkg/recorder"
)

var (
	etcdEndpoint    = flag.String("etcd-endpoint", "", "The etcd endpoint")
	etcdClientCrt   = flag.String("etcd-client-crt", "", "The etcd client certificate")
	etcdClientKey   = flag.String("etcd-client-key", "", "The etcd client key")
	etcdClientCaCrt = flag.String("etcd-client-ca-crt", "", "The etcd client CA certificate")
	namespace       = flag.String("namespace", "", "The namespace to store the secret encryption status")
	kubeconfig      = flag.String("kubeconfig", "", "Path to the kubeconfig file to use for recorder (optional)")
	kmsProviderName = flag.String("kms-provider-name", "kmsprovider", "The prefix of the KMS provider name in the encryption configuration")

	runInterval = flag.Duration("run-interval", 5*time.Minute, "The interval to run the reporter")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := setupKmsReporter(ctx); err != nil {
		klog.ErrorS(err, "Failed to setup kms-reporter")
		os.Exit(1)
	}
}

func setupKmsReporter(ctx context.Context) error {
	klog.InitFlags(nil)
	flag.Parse()

	etcdClientOperator, err := etcd.CreateEtcdClient(*etcdEndpoint, *etcdClientCrt, *etcdClientKey, *etcdClientCaCrt)
	if err != nil {
		return fmt.Errorf("Failed to create etcd client: %w", err)
	}
	defer func() {
		if err := etcdClientOperator.Close(); err != nil {
			klog.ErrorS(err, "Failed to close etcd client")
		}
	}()
	klog.Info("etcd client operator created")

	klog.Info("Starting kms-reporter")

	// Create Kubernetes clients
	etcdK8sClient, recorderK8sClient, err := createK8sClients()
	if err != nil {
		return fmt.Errorf("Failed to create k8s clients: %w", err)
	}

	// Initialize operators
	recorderOperator := recorder.NewRecorderOperator(recorderK8sClient)
	etcdOperator := reader.NewReadOperator(etcdClientOperator, etcdK8sClient, recorderOperator, *kmsProviderName)

	// Run once at startup
	if err := etcdOperator.Read(ctx, *namespace); err != nil {
		klog.ErrorS(err, "Failed to read etcd")
	}

	ticker := time.NewTicker(*runInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			klog.Info("Received termination signal, shutting down gracefully...")
			return nil
		case <-ticker.C:
			if err := etcdOperator.Read(ctx, *namespace); err != nil {
				klog.ErrorS(err, "Failed to read etcd")
			}
		}
	}
}

// createK8sClients creates separate Kubernetes clients for etcd reader and recorder
func createK8sClients() (etcdClient, recorderClient *kubernetes.Clientset, err error) {
	// Always use in-cluster config for etcd reader
	etcdConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create in-cluster config for etcd reader: %w", err)
	}
	etcdClient, err = kubernetes.NewForConfig(etcdConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create k8s client for etcd reader: %w", err)
	}

	// Use kubeconfig for recorder if set, otherwise reuse etcd config
	var recorderConfig *rest.Config
	if *kubeconfig != "" {
		klog.Infof("Using kubeconfig file for recorder: %s", *kubeconfig)
		recorderConfig, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load kubeconfig for recorder: %w", err)
		}
	} else {
		klog.Info("Using in-cluster config for recorder")
		recorderConfig = etcdConfig
	}

	recorderClient, err = kubernetes.NewForConfig(recorderConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create k8s client for recorder: %w", err)
	}

	return etcdClient, recorderClient, nil
}
