package dsm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/senhasegura/dsmcli/internal/iso"
	"github.com/spf13/viper"
)

// ApplicationResponse

type ApplicationResponse struct {
	iso.BaseResponse
	Application Application `json:"application"`
}

func (r *ApplicationResponse) Unmarshal(msg []byte) error {
	return json.Unmarshal(msg, r)
}

func (a *ApplicationResponse) SaveToFile() error {
	fmt.Println("Adding credentials to system...")

	secretDirectory := viper.GetString(KeySecretsFolder) + "/senhasegura/iso"
	if err := os.MkdirAll(secretDirectory, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(secretDirectory+"/"+KeyURL, []byte(viper.GetString(KeyURL)), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(secretDirectory+"/"+KeyClientID, []byte(a.ID), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(secretDirectory+"/"+KeyClientSecret, []byte(a.Signature), 0600); err != nil {
		return err
	}

	fmt.Println("Complete.")
	return nil
}

type Application struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	System      string   `json:"system"`
	Environment string   `json:"Environment"`
	Secrets     secrets  `json:"secrets"`
}

// Secret and secrets

type Secret struct {
	SecretID       string              `json:"secret_id"`
	SecretName     string              `json:"secret_name"`
	Identity       string              `json:"identity"`
	Version        string              `json:"version"`
	ExpirationDate string              `json:"expiration_date"`
	Engine         string              `json:"engine"`
	Data           []map[string]string `json:"data"`
}

type secrets []Secret

func (s secrets) SaveToFile() error {
	fmt.Println("Adding credentials to system...")

	secretDirectory := viper.GetString(KeySecretsFolder) + "/segura"
	if err := os.MkdirAll(secretDirectory, 0700); err != nil {
		return err
	}

	if err := RemoveContents(secretDirectory); err != nil {
		return err
	}

	for _, secret := range s {
		folder := fmt.Sprintf("%s/%s", secretDirectory, secret.Identity)
		if err := os.MkdirAll(folder, 0700); err != nil {
			return err
		}
		secret.saveToFile(folder)
	}

	fmt.Println("Complete.")
	return nil
}

func (s secrets) GetMinTTL() int64 {
	var ttl int64 = 120
	for _, secret := range s {
		ttl = secret.getMinTTL(ttl)
	}
	return ttl
}

func (s Secret) saveToFile(folder string) error {
	for _, data := range s.Data {
		for filename, content := range data {
			if err := os.WriteFile(fmt.Sprintf("%s/%s", folder, filename), []byte(content), 0600); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s Secret) getMinTTL(current int64) int64 {
	newTTL := current
	for _, data := range s.Data {
		for key, value := range data {
			if key == "TTL" && value != "" {
				ttl, err := strconv.ParseInt(value, 10, 64)
				if err == nil && ttl > 10 && ttl < newTTL {
					newTTL = ttl
				}
			}
		}
	}
	return newTTL
}

func RemoveContents(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}

	for _, name := range names {
		if err = os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// ListSecretResponse

type ListSecretResponse struct {
	iso.BaseResponse
	Secrets []Secret `json:"secrets"`
}

func (r *ListSecretResponse) Unmarshal(msg []byte) error {
	return json.Unmarshal(msg, r)
}

// VariableResponse

type VariableResponse struct {
	iso.BaseResponse
}

func (r *VariableResponse) Unmarshal(msg []byte) error {
	return json.Unmarshal(msg, r)
}
