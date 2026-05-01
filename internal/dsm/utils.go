package dsm

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

func GetConfig(verbose bool) (string, string, string, bool, bool, error) {
	if !IsSet(KeyURL, KeyClientID, KeyClientSecret) {
		return "", "", "", false, false, fmt.Errorf("authentication data not found or missing parameters")
	}
	return viper.GetString(KeyURL),
		viper.GetString(KeyClientID),
		viper.GetString(KeyClientSecret),
		verbose,
		viper.GetBool(KeyInsecure),
		nil
}

func IsSet(name ...string) bool {
	for _, n := range name {
		if viper.GetString(n) == "" {
			return false
		}
	}
	return true
}

func ReplaceSpecials(value string) string {
	value = strings.ReplaceAll(value, "+", "-")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, "=", ",")
	return value
}
