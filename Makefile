NS ?= default
REGISTRY ?= abc.azurecr.io
IMAGE_VERSION ?= v0.1.0
ETCD_ENDPOINT ?= etcd-123:456
ETCD_CLIENT_TLS_PATH ?= /etcd-tls

.PHONY: build
build:
	docker build --no-cache -t $(REGISTRY)/kms/kms-reporter:$(IMAGE_VERSION) -f kms-reporter.Dockerfile .

.PHONY: push
push:
	docker push $(REGISTRY)/kms/kms-reporter:$(IMAGE_VERSION)

.PHONY: deploy
deploy:
	export NS=$(NS); \
	export REGISTRY=$(REGISTRY); \
	export IMAGE_VERSION=$(IMAGE_VERSION); \
	export ETCD_ENDPOINT=$(ETCD_ENDPOINT); \
	export ETCD_CLIENT_TLS_PATH=$(ETCD_CLIENT_TLS_PATH); \
	export KMS_PROVIDER_NAME=$(KMS_PROVIDER_NAME); \
	envsubst < kms-reporter.yaml | kubectl apply -f -

.PHONY: clean
clean:
	export NS=$(NS); \
	export REGISTRY=$(REGISTRY); \
	export IMAGE_VERSION=$(IMAGE_VERSION); \
	export ETCD_ENDPOINT=$(ETCD_ENDPOINT); \
	export ETCD_CLIENT_TLS_PATH=$(ETCD_CLIENT_TLS_PATH); \
	envsubst < kms-reporter.yaml | kubectl delete -f - || true
	kubectl delete configmap kms-reporter -n $(NS) || true

.PHONY: all
all: build push clean deploy
