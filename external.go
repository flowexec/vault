package vault

type ExternalVaultProvider struct {
}

func (v *ExternalVaultProvider) ID() string {
	panic("not implemented yet")
}

func (v *ExternalVaultProvider) GetSecret(_ string) (Secret, error) {
	panic("not implemented yet")
}

func (v *ExternalVaultProvider) SetSecret(key string, value Secret) error {
	panic("not implemented yet")
}

func (v *ExternalVaultProvider) DeleteSecret(key string) error {
	panic("not implemented yet")
}

func (v *ExternalVaultProvider) ListSecrets() ([]string, error) {
	panic("not implemented yet")
}

func (v *ExternalVaultProvider) HasSecret(key string) (bool, error) {
	panic("not implemented yet")
}

func (v *ExternalVaultProvider) Close() error {
	return nil
}
