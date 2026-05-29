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

// yamlDocSepRe matches YAML document separators at the start of a line.
var yamlDocSepRe = regexp.MustCompile(`(?m)^---\s*$`)

// workloadKinds lists Kubernetes workload controller kinds we parse.
var workloadKinds = map[string]bool{
	"Deployment":  true,
	"DaemonSet":   true,
	"StatefulSet": true,
	"Job":         true,
	"CronJob":     true,
	"ReplicaSet":  true,
}

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

		// Finding 6: log file processing errors to stderr instead of silently discarding
		if err := processFile(path, opts, result); err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", path, err)
		}
		return nil
	})
}

func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}

func processFile(path string, opts *Options, result *models.LoadedResources) error {
	// NEW-6: use os.Open + Fstat to eliminate TOCTOU window
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Fstat on the open file descriptor (no TOCTOU)
	info, err := f.Stat()
	if err != nil {
		return err
	}

	// Skip symlinks
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("symlink detected, skipping")
	}

	if info.Size() > opts.MaxFileSize {
		return fmt.Errorf("file %q exceeds max size (%d > %d)", path, info.Size(), opts.MaxFileSize)
	}

	// Read from the already-opened file descriptor
	data := make([]byte, info.Size())
	_, err = f.Read(data)
	if err != nil {
		return err
	}

	content := string(data)

	// Preprocess Go templates so the YAML parser doesn't choke
	content = goTemplateRe.ReplaceAllString(content, "placeholder-value")

	// Design observation: use package-level compiled regex
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
	return yamlDocSepRe.Split(content, -1)
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
		// Finding 8: warn on duplicate map keys
		if _, exists := result.ClusterRoles[name]; exists {
			fmt.Fprintf(os.Stderr, "warning: duplicate ClusterRole %q found in %s, previous entry will be overwritten\n", name, file)
		}
		result.ClusterRoles[name] = &models.ClusterRoleData{
			Rules: rules,
			File:  file,
			Doc:   doc,
		}

	case "Role":
		rules := extractRules(doc)
		key := namespace + "/" + name
		// Finding 8: warn on duplicate map keys
		if _, exists := result.Roles[key]; exists {
			fmt.Fprintf(os.Stderr, "warning: duplicate Role %q found in %s, previous entry will be overwritten\n", key, file)
		}
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
		if _, exists := result.ServiceAccounts[key]; exists {
			fmt.Fprintf(os.Stderr, "warning: duplicate ServiceAccount %q found in %s, previous entry will be overwritten\n", key, file)
		}
		result.ServiceAccounts[key] = &models.SAData{
			Name:      name,
			Namespace: namespace,
			File:      file,
			Doc:       doc,
		}

	case "Pod":
		saName := extractServiceAccountName(doc)
		key := namespace + "/" + name
		if _, exists := result.Pods[key]; exists {
			fmt.Fprintf(os.Stderr, "warning: duplicate Pod %q found in %s, previous entry will be overwritten\n", key, file)
		}
		result.Pods[key] = &models.PodData{
			Name:               name,
			Namespace:          namespace,
			ServiceAccountName: saName,
			File:               file,
			Doc:                doc,
		}

	default:
		// Finding 5: parse workload controllers
		if workloadKinds[kind] {
			saName := extractWorkloadServiceAccountName(doc, kind)
			// NEW-2: include Kind in key to prevent cross-kind collisions
			key := kind + "/" + namespace + "/" + name
			if _, exists := result.Workloads[key]; exists {
				fmt.Fprintf(os.Stderr, "warning: duplicate %s %q found in %s, previous entry will be overwritten\n", kind, key, file)
			}
			result.Workloads[key] = &models.WorkloadData{
				Name:               name,
				Kind:               kind,
				Namespace:          namespace,
				ServiceAccountName: saName,
				File:               file,
				Doc:                doc,
			}
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

// extractWorkloadServiceAccountName extracts the serviceAccountName from workload controllers.
// For CronJob, the SA is nested under spec.jobTemplate.spec.template.spec.
// For Job, it's under spec.template.spec.
// For Deployment/DaemonSet/StatefulSet/ReplicaSet, it's under spec.template.spec.
func extractWorkloadServiceAccountName(doc map[string]interface{}, kind string) string {
	spec, ok := doc["spec"].(map[string]interface{})
	if !ok {
		return "default"
	}

	if kind == "CronJob" {
		jobTemplate, ok := spec["jobTemplate"].(map[string]interface{})
		if !ok {
			return "default"
		}
		spec, ok = jobTemplate["spec"].(map[string]interface{})
		if !ok {
			return "default"
		}
	}

	template, ok := spec["template"].(map[string]interface{})
	if !ok {
		return "default"
	}

	podSpec, ok := template["spec"].(map[string]interface{})
	if !ok {
		return "default"
	}

	saName, ok := podSpec["serviceAccountName"].(string)
	if !ok || saName == "" {
		return "default"
	}
	return saName
}
