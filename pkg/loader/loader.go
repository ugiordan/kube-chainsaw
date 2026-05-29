package loader

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ugiordan/kube-chainsaw/pkg/models"
	"sigs.k8s.io/yaml"
)

const (
	DefaultMaxFileSize    = 10 * 1024 * 1024 // 10MB
	DefaultMaxDocsPerFile = 10000
)

// DefaultExcludeDirs contains directory names skipped during traversal.
var DefaultExcludeDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"bin":          true,
}

// goTemplateRe matches Go template expressions like {{ .Values.foo }}.
var goTemplateRe = regexp.MustCompile(`\{\{[^}]+\}\}`)

// Options configures the manifest loader.
type Options struct {
	ExcludeDirs        []string
	UseDefaultExcludes bool
	MaxFileSize        int64
	MaxDocsPerFile     int
}

// DefaultOptions returns options with sensible defaults.
func DefaultOptions() *Options {
	return &Options{
		UseDefaultExcludes: true,
		MaxFileSize:        DefaultMaxFileSize,
		MaxDocsPerFile:     DefaultMaxDocsPerFile,
	}
}

// LoadManifests walks the given paths (files or directories) and parses all
// YAML/JSON manifests into LoadedResources.
func LoadManifests(paths []string, opts *Options) (*models.LoadedResources, error) {
	if opts == nil {
		opts = DefaultOptions()
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	if opts.MaxDocsPerFile <= 0 {
		opts.MaxDocsPerFile = DefaultMaxDocsPerFile
	}

	excludes := buildExcludes(opts)
	result := models.NewLoadedResources()

	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, fmt.Errorf("cannot access %q: %w", p, err)
		}

		// Skip symlinks at the top level
		if info.Mode()&fs.ModeSymlink != 0 {
			continue
		}

		if info.IsDir() {
			if err := walkDir(p, excludes, opts, result); err != nil {
				return nil, err
			}
		} else {
			if err := processFile(p, opts, result); err != nil {
				// Skip files that fail to parse (non-fatal)
				continue
			}
		}
	}

	return result, nil
}

func buildExcludes(opts *Options) map[string]bool {
	excludes := make(map[string]bool)
	if opts.UseDefaultExcludes {
		for k, v := range DefaultExcludeDirs {
			excludes[k] = v
		}
	}
	for _, d := range opts.ExcludeDirs {
		excludes[d] = true
	}
	return excludes
}

func walkDir(root string, excludes map[string]bool, opts *Options, result *models.LoadedResources) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}

		// Skip symlinks
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if excludes[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}

		if !isYAMLFile(path) {
			return nil
		}

		// processFile errors are non-fatal: skip malformed files
		_ = processFile(path, opts, result)
		return nil
	})
}

func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}

func processFile(path string, opts *Options, result *models.LoadedResources) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.Size() > opts.MaxFileSize {
		return fmt.Errorf("file %q exceeds max size (%d > %d)", path, info.Size(), opts.MaxFileSize)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)

	// Preprocess Go templates so the YAML parser doesn't choke
	content = goTemplateRe.ReplaceAllString(content, "placeholder-value")

	docs := splitYAMLDocs(content)

	if len(docs) > opts.MaxDocsPerFile {
		return fmt.Errorf("file %q has too many documents (%d > %d)", path, len(docs), opts.MaxDocsPerFile)
	}

	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		var parsed map[string]interface{}
		if err := yaml.Unmarshal([]byte(doc), &parsed); err != nil {
			continue // skip unparseable documents
		}

		if parsed == nil {
			continue
		}

		categorize(parsed, path, result)
	}

	return nil
}

// splitYAMLDocs splits a multi-document YAML string on "---" separators.
// Only splits on "---" that appears at the start of a line (not inside
// multiline strings, which the simple approach can't fully handle, but
// works well enough for Kubernetes manifests).
func splitYAMLDocs(content string) []string {
	// Split on document separator at the start of a line
	re := regexp.MustCompile(`(?m)^---\s*$`)
	return re.Split(content, -1)
}

func categorize(doc map[string]interface{}, file string, result *models.LoadedResources) {
	kind, _ := doc["kind"].(string)
	metadata, _ := doc["metadata"].(map[string]interface{})
	if metadata == nil {
		return
	}
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)

	switch kind {
	case "ClusterRole":
		rules := extractRules(doc)
		result.ClusterRoles[name] = &models.ClusterRoleData{
			Rules: rules,
			File:  file,
			Doc:   doc,
		}

	case "Role":
		rules := extractRules(doc)
		key := namespace + "/" + name
		result.Roles[key] = &models.RoleData{
			Rules:     rules,
			Namespace: namespace,
			File:      file,
			Doc:       doc,
		}

	case "ClusterRoleBinding":
		bd := extractBinding(doc, name, "", file)
		result.ClusterRoleBindings = append(result.ClusterRoleBindings, bd)

	case "RoleBinding":
		bd := extractBinding(doc, name, namespace, file)
		result.RoleBindings = append(result.RoleBindings, bd)

	case "ServiceAccount":
		key := namespace + "/" + name
		result.ServiceAccounts[key] = &models.SAData{
			Name:      name,
			Namespace: namespace,
			File:      file,
			Doc:       doc,
		}

	case "Pod":
		saName := extractServiceAccountName(doc)
		key := namespace + "/" + name
		result.Pods[key] = &models.PodData{
			Name:               name,
			Namespace:          namespace,
			ServiceAccountName: saName,
			File:               file,
			Doc:                doc,
		}
	}
}

func extractRules(doc map[string]interface{}) []map[string]interface{} {
	rulesRaw, ok := doc["rules"]
	if !ok {
		return nil
	}

	rulesSlice, ok := rulesRaw.([]interface{})
	if !ok {
		return nil
	}

	var rules []map[string]interface{}
	for _, r := range rulesSlice {
		rMap, ok := r.(map[string]interface{})
		if ok {
			rules = append(rules, rMap)
		}
	}
	return rules
}

func extractBinding(doc map[string]interface{}, name, namespace, file string) *models.BindingData {
	bd := &models.BindingData{
		Name:      name,
		Namespace: namespace,
		File:      file,
		Doc:       doc,
	}

	if roleRef, ok := doc["roleRef"].(map[string]interface{}); ok {
		bd.RoleRef = roleRef
	}

	if subjects, ok := doc["subjects"].([]interface{}); ok {
		for _, s := range subjects {
			if sMap, ok := s.(map[string]interface{}); ok {
				bd.Subjects = append(bd.Subjects, sMap)
			}
		}
	}

	return bd
}

func extractServiceAccountName(doc map[string]interface{}) string {
	spec, ok := doc["spec"].(map[string]interface{})
	if !ok {
		return "default"
	}

	saName, ok := spec["serviceAccountName"].(string)
	if !ok || saName == "" {
		return "default"
	}
	return saName
}
