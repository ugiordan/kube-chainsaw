Output site/docs/images/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 600
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

# Build the binary first (hidden from recording)
Hide
Type "cd /Users/ugogiordano/workdir/rhoai/kube-chainsaw && go build -o /tmp/kube-chainsaw ./cmd/kube-chainsaw/ && export PATH=/tmp:$PATH"
Enter
Sleep 3s
Show

Type "# Scan Kubernetes RBAC manifests for privilege escalation"
Enter
Sleep 1s

Type "kube-chainsaw testdata/dangerous/ --fail-on HIGH"
Enter
Sleep 3s

Type ""
Sleep 2s

Type "# Generate SARIF for GitHub Code Scanning"
Enter
Sleep 500ms

Type "kube-chainsaw testdata/dangerous/ --output results.sarif --quiet"
Enter
Sleep 2s

Type "cat results.sarif | head -20"
Enter
Sleep 2s

Type ""
Sleep 1s

Type "# Suppress accepted risks"
Enter
Sleep 500ms

Type "cat <<'EOF' > suppressions.yaml"
Enter
Type "suppressions:"
Enter
Type "  - rule_id: KC-006"
Enter
Type "    resource_name: secrets-cluster-wide-role"
Enter
Type "    reason: Operator needs cluster-wide secret access"
Enter
Type "EOF"
Enter
Sleep 1s

Type "kube-chainsaw testdata/dangerous/secrets-cluster-wide.yaml --suppressions suppressions.yaml"
Enter
Sleep 2s

Type ""
Sleep 2s
