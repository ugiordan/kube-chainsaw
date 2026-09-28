package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
)

var credentialSecretTypes = map[string]bool{
	"kubernetes.io/basic-auth":       true,
	"kubernetes.io/dockercfg":        true,
	"kubernetes.io/dockerconfigjson": true,
	"kubernetes.io/ssh-auth":         true,
	"kubernetes.io/tls":              true,
	"bootstrap.kubernetes.io/token":  true,
}

var credentialKeyNames = map[string]bool{
	"accesskey":         true,
	"apikey":            true,
	"auth":              true,
	"authorization":     true,
	"clientcertificate": true,
	"clientkey":         true,
	"clientsecret":      true,
	"credential":        true,
	"credentials":       true,
	"jwt":               true,
	"password":          true,
	"passwd":            true,
	"private":           true,
	"privatekey":        true,
	"secret":            true,
	"token":             true,
}

func analyzeSecrets(resources *models.LoadedResources) []models.Finding {
	keys := make([]string, 0, len(resources.Secrets))
	for key := range resources.Secrets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var findings []models.Finding
	for _, key := range keys {
		secret := resources.Secrets[key]
		if secret == nil {
			continue
		}
		secretType, _ := secret.Doc["type"].(string)
		if isLongLivedServiceAccountToken(secret.Doc, secretType) {
			f := newFinding(RuleServiceAccountTokenSecret, models.SeverityHigh, secret.File, "Secret", secret.Name, secret.Namespace)
			f.Description = fmt.Sprintf("Secret %q is a long-lived ServiceAccount token Secret", secret.Name)
			findings = appendIfNew(findings, f)
			continue
		}

		keys, knownCredentialType := credentialKeys(secret.Doc, secretType)
		if !knownCredentialType && len(keys) == 0 {
			continue
		}
		detail := "credential-like keys: " + strings.Join(keys, ", ")
		if knownCredentialType {
			detail = "type " + secretType
		}
		f := newFinding(RuleCredentialSecret, models.SeverityWarning, secret.File, "Secret", secret.Name, secret.Namespace)
		f.Description = fmt.Sprintf("Secret %q contains credential material in a static manifest (%s)", secret.Name, detail)
		findings = appendIfNew(findings, f)
	}

	return findings
}

func isLongLivedServiceAccountToken(doc map[string]interface{}, secretType string) bool {
	if secretType == "kubernetes.io/service-account-token" {
		return true
	}
	annotations, _ := asStringMap(doc["metadata.annotations"])
	if annotations == nil {
		metadata, _ := asStringMap(doc["metadata"])
		annotations, _ = asStringMap(metadata["annotations"])
	}
	_, hasServiceAccount := annotations["kubernetes.io/service-account.name"]
	data, _ := asStringMap(doc["data"])
	_, hasToken := data["token"]
	if !hasToken {
		stringData, _ := asStringMap(doc["stringData"])
		_, hasToken = stringData["token"]
	}
	return hasServiceAccount && hasToken
}

func credentialKeys(doc map[string]interface{}, secretType string) ([]string, bool) {
	data, _ := asStringMap(doc["data"])
	stringData, _ := asStringMap(doc["stringData"])
	knownType := credentialSecretTypes[secretType] && (len(data) > 0 || len(stringData) > 0)
	if knownType {
		return nil, true
	}

	var keys []string
	for key := range data {
		if isCredentialKey(key) {
			keys = appendUnique(keys, key)
		}
	}
	for key := range stringData {
		if isCredentialKey(key) {
			keys = appendUnique(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, false
}

func isCredentialKey(key string) bool {
	normalized := strings.ToLower(key)
	if credentialKeyNames[normalized] {
		return true
	}
	parts := strings.FieldsFunc(normalized, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, part := range parts {
		if credentialKeyNames[part] {
			return true
		}
	}
	return false
}
