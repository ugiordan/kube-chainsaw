# Custom Exclusions

kube-chainsaw provides directory and file exclusion options to skip vendor code, test fixtures, and other non-production manifests.

---

## Default Exclusions

By default, kube-chainsaw skips these directories:

- `.git/`
- `vendor/`
- `node_modules/`
- `bin/`

These exclusions prevent noise from third-party dependencies and build artifacts.

---

## Custom Exclusions

Use `--exclude-dirs` to add custom exclusions:

```bash
kube-chainsaw k8s/ --exclude-dirs build,dist,tmp
```

Comma-separated directory names (not paths). The scanner will skip any directory with these names at any depth. Custom exclusions are added to the default list.

---

## Disabling Default Exclusions

Use `--no-default-excludes` to scan all directories, including `.git`, vendor, and node_modules:

```bash
kube-chainsaw k8s/ --no-default-excludes
```

This is useful for auditing third-party Helm charts or operator manifests.

---

## Combining Exclusions

Add custom exclusions while keeping defaults:

```bash
kube-chainsaw k8s/ --exclude-dirs staging,old-configs
```

Override defaults completely:

```bash
kube-chainsaw k8s/ --no-default-excludes --exclude-dirs vendor
```

This scans `.git/` and `bin/` but skips `vendor/`.

---

## Exclusion Behavior

Exclusions are applied to directory names, not full paths:

```
k8s/
  prod/          # Scanned
  staging/       # Excluded if --exclude-dirs staging
  infra/
    staging/     # Also excluded (name matches)
```

Directory exclusions apply at the filesystem level. To suppress findings from specific files without excluding them from loading, use a suppression file (see [Suppressions Guide](suppressions.md)).

---

## Examples

### Exclude staging and dev environments:

```bash
kube-chainsaw k8s/ --exclude-dirs staging,dev
```

### Audit vendor Helm charts:

```bash
kube-chainsaw charts/ --no-default-excludes
```

### Scan only production manifests:

```bash
kube-chainsaw k8s/prod/
```

---

## Next Steps

- [Suppressions](suppressions.md): Suppress specific findings while scanning excluded files
- [CLI Reference](../reference/cli.md): Full list of command-line options
