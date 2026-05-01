package cmd

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/senhasegura/dsmcli/internal/dsm"
	"github.com/senhasegura/dsmcli/internal/iso"
)

var kv map[string]string

var Verbose bool
var ToolName string
var Environment string
var System string
var ApplicationName string
var Format string

var RunbCmd = &cobra.Command{
	Use:   "runb",
	Short: "Running Belt plugin to insert/get/replace environment variables in most CI/CD pipelines.",
	Long:  `Running Belt plugin to insert/get/replace environment variables in most CI/CD pipelines.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if viper.GetBool(dsm.KeyDisableRunb) {
			return fmt.Errorf("SENHASEGURA_DISABLE_RUNB is set to true. Plugin is disabled.")
		}

		client, appClient, err := registerApplication()
		if err != nil {
			return err
		}

		envVars := loadEnvVars()
		mapVars := loadMapVars()

		varClient := dsm.NewVariableClient(&client)
		if _, err = varClient.Register(envVars, mapVars); err != nil {
			return fmt.Errorf("error when posting variables in senhasegura: %w", err)
		}

		secretsResponse, err := appClient.ListSecrets()
		if err != nil {
			return err
		}

		if err = injectEnvironmentVariables(secretsResponse.Secrets); err != nil {
			return err
		}

		return deleteCICDVariables()
	},
}

func init() {
	RunbCmd.Flags().BoolVarP(&Verbose, "verbose", "v", false, "Verbose mode")
	RunbCmd.Flags().StringVarP(&ApplicationName, "application", "a", "", "Application name (required)")
	RunbCmd.Flags().StringVarP(&System, "system", "s", "", "Application system (required)")
	RunbCmd.Flags().StringVarP(&Environment, "environment", "e", "", "Application environment (required)")
	RunbCmd.Flags().StringVarP(&ToolName, "tool", "t", "linux", "Tool name [github, azure-devops, bamboo, bitbucket, circleci, teamcity, linux, custom]")
	RunbCmd.Flags().StringVarP(&Format, "format", "f", "", "Custom format to inject secrets using Go templating system")
	RunbCmd.MarkFlagRequired("application")
	RunbCmd.MarkFlagRequired("system")
	RunbCmd.MarkFlagRequired("environment")
}

func v(format string, a ...interface{}) {
	if Verbose {
		fmt.Printf(format, a...)
	}
}

func registerApplication() (iso.Client, dsm.DsmClient, error) {
	seguraUrl, clientID, clientSecret, verbose, insecure, err := dsm.GetConfig(Verbose)
	if err != nil {
		return iso.Client{}, dsm.DsmClient{}, err
	}
	client, err := iso.NewClient(seguraUrl, clientID, clientSecret, verbose, insecure)
	if err != nil {
		return iso.Client{}, dsm.DsmClient{}, err
	}

	appClient, err := dsm.NewDsmClient(&client, ApplicationName, Environment, System)
	if err != nil {
		return client, appClient, err
	}

	/*appResponse, err := appClient.RegisterApplication()
	if err != nil {
		return client, appClient, err
	}*/

	client.DefineNewCredentials(viper.GetString(dsm.KeyClientID), viper.GetString(dsm.KeyClientSecret))
	return client, appClient, nil
}

func loadEnvVars() string {
	envVars := base64.StdEncoding.EncodeToString([]byte(strings.Join(os.Environ(), "\n")))
	return dsm.ReplaceSpecials(envVars)
}

func loadMapVars() string {
	if !dsm.IsSet(dsm.KeyMappingFile) {
		v("Mapping file not found, proceeding...\n")
	} else {
		v("Using mapping file: %s\n", viper.GetString(dsm.KeyMappingFile))
	}

	content, err := os.ReadFile(viper.GetString(dsm.KeyMappingFile))
	if err != nil {
		return ""
	}

	return dsm.ReplaceSpecials(base64.StdEncoding.EncodeToString(content))
}

func injectEnvironmentVariables(secrets []dsm.Secret) error {
	switch ToolName {
	case "github":
		return inject(secrets, "echo '%k=%v' >> $GITHUB_ENV\n")
	case "azure-devops":
		return inject(secrets, "echo '##vso[task.setvariable variable=%k;issecret=true;]%v'\n")
	case "bamboo":
		return inject(secrets, "(%k)=(.[%v])\n")
	case "bitbucket":
		return inject(secrets, "export (%k)=\"(.[%v])\"\n")
	case "circleci":
		return inject(secrets, "echo '\"'\"'export (%k)=\"(.[%v])\"'\"'\"' >> $BASH_ENV\n")
	case "teamcity":
		return inject(secrets, "echo '\"'\"'##teamcity[setParameter name=\"(%k)\" value=\"(.[%v])\"]'\"'\"'\"\n")
	case "linux":
		return inject(secrets, "declare -x %k='%v'\n")
	case "custom":
		if Format == "" {
			return fmt.Errorf("format is required when using custom tool")
		}
		return inject(secrets, Format)
	default:
		return fmt.Errorf("tool '%s' is invalid, it must be one of the following values: github, azure-devops, bamboo, bitbucket, circleci, teamcity, linux or custom", ToolName)
	}
}

func inject(secrets []dsm.Secret, format string) error {
	v("Injecting secrets!\n")

	kv = convertJSONToKV(secrets)
	if len(kv) == 0 {
		v("No secrets to be injected!\n")
		return nil
	}

	secretsFile := viper.GetString(dsm.KeySecretsFile)
	if secretsFile == "" {
		secretsFile = ".runb.vars"
	}

	file, err := os.OpenFile(secretsFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	if strings.Contains(format, "{{") {
		v("Using Go template format\n")
		tmpl, err := template.New("custom").Parse(format)
		if err != nil {
			return fmt.Errorf("error parsing custom format: %w", err)
		}
		if err := tmpl.Execute(writer, kv); err != nil {
			return fmt.Errorf("error executing custom format template: %w", err)
		}
	} else {
		v("Using placeholder format\n")
		for key, value := range kv {
			v("Injecting secret into %s: %s.....", secretsFile, key)
			line := strings.ReplaceAll(format, "%k", key)
			line = strings.ReplaceAll(line, "%v", value)
			if !strings.HasSuffix(line, "\n") {
				line += "\n"
			}
			if _, err = writer.WriteString(line); err != nil {
				return err
			}
			v("Success!\n")
		}
	}

	v("Secrets injected!\n")
	return nil
}

func convertJSONToKV(secrets []dsm.Secret) map[string]string {
	result := make(map[string]string)
	for _, secret := range secrets {
		for _, data := range secret.Data {
			for key, value := range data {
				result[key] = value
			}
		}
	}
	return result
}

func deleteCICDVariables() error {
	v("Deleting %s variables...\n", ToolName)

	if len(kv) == 0 {
		v("No variables to be deleted!\n")
		return nil
	}

	switch ToolName {
	case "gitlab":
		return deleteGitLabVars()
	case "github", "azure-devops", "bamboo", "bitbucket", "circleci", "teamcity", "linux", "custom":
		v("Is not possible to delete %s variables!\n", ToolName)
	default:
		return fmt.Errorf("tool '%s' is invalid, it must be one of the following values: github, azure-devops, bamboo, bitbucket, circleci, teamcity or linux", ToolName)
	}

	v("Finish\n")
	return nil
}

func deleteGitLabVars() error {
	if !dsm.IsSet(dsm.KeyGitLabToken, dsm.KeyGitLabAPIURL, dsm.KeyGitLabProjectID) {
		v("Deletion failed\n")
		v("To delete gitlab variables, you need to define the configs GITLAB_ACCESS_TOKEN, CI_API_V4_URL and CI_PROJECT_ID\n")
		return nil
	}

	if len(kv) == 0 {
		v("Deletion failed\n")
		v("Has no credentials to exclude variables on '%s' tool ...\n", ToolName)
		return nil
	}

	apiURL, err := url.ParseRequestURI(viper.GetString("CI_API_V4_URL"))
	if err != nil {
		return fmt.Errorf("invalid CI_API_V4_URL: %w", err)
	}
	host := apiURL.Scheme + "://" + apiURL.Host
	basePath := strings.TrimRight(apiURL.Path, "/")
	headers := map[string]string{"PRIVATE-TOKEN": viper.GetString("GITLAB_ACCESS_TOKEN")}

	for key := range kv {
		v("Deleting %s variable\n", key)

		resource := fmt.Sprintf("%s/projects/%s/variables/%s", basePath, viper.GetString("CI_PROJECT_ID"), key)
		_, err := iso.DoRequest(host, resource, url.Values{}, headers, http.MethodDelete, viper.GetBool("insecure"))
		if err != nil {
			v("Failed trying to delete '%s' variable\n", err.Error())
			continue
		}

		v("Deleted\n")
	}
	return nil
}
