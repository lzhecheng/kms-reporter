package reader

// EncryptionConfiguration represents the encryption configuration structure
type EncryptionConfiguration struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Resources  []Resource `yaml:"resources"`
}

type Resource struct {
	Providers []Provider `yaml:"providers"`
	Resources []string   `yaml:"resources"`
}

type Provider struct {
	KMS      *KMSProvider `yaml:"kms,omitempty"`
	Identity *struct{}    `yaml:"identity,omitempty"`
}

type KMSProvider struct {
	APIVersion string `yaml:"apiVersion"`
	Endpoint   string `yaml:"endpoint"`
	Name       string `yaml:"name"`
}

// EncryptionAnalysisResult holds the result of analyzing secret encryption status
type EncryptionAnalysisResult struct {
	EncryptedSecrets            []string
	UnencryptedSecrets          []string
	AllSecretsUseLatestProvider bool
}
