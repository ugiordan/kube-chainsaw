package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBinary builds the binary once and returns its path.
func testBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "kube-chainsaw")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build failed: %s", string(out))
	return binary
}

func TestCLI_DangerousExitCode(t *testing.T) {
	bin := testBinary(t)
	cmd := exec.Command(bin, "../../testdata/dangerous/")
	out, err := cmd.CombinedOutput()

	// Should exit non-zero (CRITICAL findings present)
	require.Error(t, err, "expected non-zero exit code for dangerous manifests")
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Contains(t, string(out), "CRITICAL")
}

func TestCLI_CleanExitCode(t *testing.T) {
	bin := testBinary(t)
	cmd := exec.Command(bin, "../../testdata/clean/")
	out, err := cmd.CombinedOutput()

	// Should exit 0 (no CRITICAL findings)
	assert.NoError(t, err, "expected zero exit code for clean manifests, got output: %s", string(out))
}

func TestCLI_FailOnWarning(t *testing.T) {
	bin := testBinary(t)
	cmd := exec.Command(bin, "--fail-on", "WARNING", "../../testdata/clean/")
	_, err := cmd.CombinedOutput()

	// clean/ has WARNING findings, so --fail-on WARNING should exit 1
	require.Error(t, err, "expected non-zero exit code with --fail-on WARNING")
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, 1, exitErr.ExitCode())
}

func TestCLI_JSONFormat(t *testing.T) {
	bin := testBinary(t)
	cmd := exec.Command(bin, "--format", "json", "../../testdata/clean/")
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err)

	// Verify valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(out, &parsed)
	require.NoError(t, err, "output should be valid JSON: %s", string(out))
	assert.Contains(t, parsed, "findings")
}

func TestCLI_SARIFFormat(t *testing.T) {
	bin := testBinary(t)
	cmd := exec.Command(bin, "--format", "sarif", "../../testdata/clean/")
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err)

	// Verify valid SARIF JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(out, &parsed)
	require.NoError(t, err, "output should be valid JSON")
	assert.Equal(t, "2.1.0", parsed["version"])
}

func TestCLI_OutputFile(t *testing.T) {
	bin := testBinary(t)
	outFile := filepath.Join(t.TempDir(), "report.json")
	cmd := exec.Command(bin, "--output", outFile, "--quiet", "../../testdata/clean/")
	_, err := cmd.CombinedOutput()
	assert.NoError(t, err)

	// Verify file was written and is valid JSON
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Contains(t, parsed, "findings")
}

func TestCLI_OutputFileSARIF(t *testing.T) {
	bin := testBinary(t)
	outFile := filepath.Join(t.TempDir(), "report.sarif")
	cmd := exec.Command(bin, "--output", outFile, "--quiet", "../../testdata/clean/")
	_, err := cmd.CombinedOutput()
	assert.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "2.1.0", parsed["version"])
}

func TestCLI_OutputFormatOverride(t *testing.T) {
	bin := testBinary(t)
	outFile := filepath.Join(t.TempDir(), "report.txt")
	cmd := exec.Command(bin, "--output", outFile, "--output-format", "sarif", "--quiet", "../../testdata/clean/")
	_, err := cmd.CombinedOutput()
	assert.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "2.1.0", parsed["version"])
}

func TestCLI_Version(t *testing.T) {
	bin := testBinary(t)
	cmd := exec.Command(bin, "--version")
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err)
	assert.Contains(t, string(out), "dev")
}

func TestCLI_Quiet(t *testing.T) {
	bin := testBinary(t)
	cmd := exec.Command(bin, "--quiet", "../../testdata/clean/")
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err)
	assert.Empty(t, strings.TrimSpace(string(out)), "quiet mode should produce no stdout")
}

func TestCLI_Suppressions(t *testing.T) {
	bin := testBinary(t)

	// Create a suppressions file that suppresses the WARNING findings in clean/
	supContent := `suppressions:
  - rule_id: KC-012
    resource_name: operator-elevated-legitimate-role
    reason: "expected for operator"
  - rule_id: KC-014
    resource_name: operator-elevated-legitimate-binding
    reason: "expected"
  - rule_id: KC-014
    resource_name: rolebinding-clusterrole-namespaced-binding
    reason: "expected"
`
	dir := t.TempDir()
	supFile := filepath.Join(dir, "sup.yaml")
	require.NoError(t, os.WriteFile(supFile, []byte(supContent), 0644))

	// With --fail-on WARNING, clean/ would normally fail.
	// With suppressions, all findings are suppressed, so it should pass.
	cmd := exec.Command(bin, "--fail-on", "WARNING", "--suppressions", supFile, "../../testdata/clean/")
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err, "all findings suppressed, should exit 0. Output: %s", string(out))
}

func TestCLI_NoArgs(t *testing.T) {
	bin := testBinary(t)
	cmd := exec.Command(bin)
	_, err := cmd.CombinedOutput()
	require.Error(t, err, "should fail without args")
}

func TestCLI_InvalidPath(t *testing.T) {
	bin := testBinary(t)
	cmd := exec.Command(bin, "/nonexistent/path")
	_, err := cmd.CombinedOutput()
	require.Error(t, err, "should fail with invalid path")
}
