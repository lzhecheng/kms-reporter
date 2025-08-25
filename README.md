# Intro

**KMS Reporter** is a Kubernetes tool that provides visibility into secret encryption status across your cluster.

**Background:** Key Management Service (KMS) enables encryption of Kubernetes secrets at rest in etcd using external key management systems. However, when KMS is enabled, administrators lack visibility into which secrets are actually encrypted and which provider version was used - critical information for security compliance and key rotation operations.

**Solution:** KMS Reporter bridges this gap by:
- Reading secret data directly from etcd to analyze encryption status
- Comparing against current KMS provider configurations
- Publishing encryption status reports as ConfigMaps for easy access
- Running continuously to track encryption state changes

This enables administrators to verify encryption coverage, monitor key rotation progress, and maintain security compliance across their Kubernetes secrets.

# Usage
```
export NS=<namespace>
export REGISTRY=registry.azurecr.io
az acr login -n $REGISTRY
export ETCD_ENDPOINT=<etcd-endpoint>
export ETCD_CLIENT_TLS_PATH=<tls-path>
export KMS_PROVIDER_NAME=<kms-provider-name>

make build push
make clean
make deploy
```
