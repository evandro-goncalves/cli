package dsm

import (
	"fmt"
	"net/url"

	"github.com/senhasegura/dsmcli/internal/iso"
)

type DsmClient struct {
	client      *iso.Client
	name        string
	system      string
	environment string
}

func NewDsmClient(client *iso.Client, name string, environment string, system string) (DsmClient, error) {
	if name == "" {
		return DsmClient{}, fmt.Errorf("application name must be defined")
	}
	if environment == "" {
		return DsmClient{}, fmt.Errorf("environment must be defined")
	}
	if system == "" {
		return DsmClient{}, fmt.Errorf("system must be defined")
	}
	return DsmClient{name: name, environment: environment, system: system, client: client}, nil
}

func (a *DsmClient) RegisterApplication() (ApplicationResponse, error) {
	a.client.V("Registering Application on DevSecOps\n")
	if err := a.client.Authenticate(); err != nil {
		return ApplicationResponse{}, err
	}

	data := url.Values{
		"application": {a.name},
		"environment": {a.environment},
		"system":      {a.system},
	}

	var appResp ApplicationResponse
	if err := a.client.Post("/iso/dapp/Application", data, &appResp); err != nil {
		return ApplicationResponse{}, err
	}

	a.client.V("Application register success\n")
	return appResp, nil
}

func (a *DsmClient) GetApplication() (ApplicationResponse, error) {
	if err := a.client.Authenticate(); err != nil {
		return ApplicationResponse{}, err
	}

	var appResp ApplicationResponse
	if err := a.client.Get("/iso/dapp/Application", url.Values{}, &appResp); err != nil {
		return ApplicationResponse{}, err
	}

	return appResp, nil
}

func (a *DsmClient) ListSecrets() (ListSecretResponse, error) {
	a.client.V("Finding secrets from application\n")
	if err := a.client.Authenticate(); err != nil {
		return ListSecretResponse{}, err
	}

	var resp ListSecretResponse
	if err := a.client.Get("/iso/sctm/secret", url.Values{}, &resp); err != nil {
		return ListSecretResponse{}, err
	}

	return resp, nil
}

func (a *DsmClient) GetClient() *iso.Client {
	return a.client
}

type VariableClient struct {
	client *iso.Client
}

func NewVariableClient(client *iso.Client) VariableClient {
	return VariableClient{client: client}
}

func (a *VariableClient) Register(envVars string, mapVars string) (VariableResponse, error) {
	a.client.V("Posting variables in senhasegura...\n")
	if err := a.client.Authenticate(); err != nil {
		return VariableResponse{}, err
	}

	data := url.Values{
		"env": {envVars},
		"map": {mapVars},
	}

	var varResp VariableResponse
	if err := a.client.Post("/iso/cicd/variables", data, &varResp); err != nil {
		return VariableResponse{}, err
	}

	a.client.V("Posting variables successfully\n")
	return varResp, nil
}
