package dsm

const (
	// Cobra flag names (also bound as viper keys)
	KeyConfig   = "config"
	KeyInsecure = "insecure"

	// Senhasegura environment variables
	KeyURL           = "SENHASEGURA_URL"
	KeyClientID      = "SENHASEGURA_CLIENT_ID"
	KeyClientSecret  = "SENHASEGURA_CLIENT_SECRET"
	KeyConfigFile    = "SENHASEGURA_CONFIG_FILE"
	KeyDisableRunb   = "SENHASEGURA_DISABLE_RUNB"
	KeyMappingFile   = "SENHASEGURA_MAPPING_FILE"
	KeySecretsFile   = "SENHASEGURA_SECRETS_FILE"
	KeySecretsFolder = "SENHASEGURA_SECRETS_FOLDER"

	// GitLab CI environment variables
	KeyGitLabToken     = "GITLAB_ACCESS_TOKEN"
	KeyGitLabAPIURL    = "CI_API_V4_URL"
	KeyGitLabProjectID = "CI_PROJECT_ID"
)
