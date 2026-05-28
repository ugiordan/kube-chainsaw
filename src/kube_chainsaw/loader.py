"""YAML manifest loader for Kubernetes resources."""

import re
import sys
from pathlib import Path
from typing import List, Optional, Set, Union

import yaml

from .models import LoadedResources

# Default directories to exclude from scanning
DEFAULT_EXCLUDE_DIRS = {".git", "vendor", "node_modules", "bin"}

# Default limits
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
DEFAULT_MAX_DOCS_PER_FILE = 10000


def _is_go_template(filepath: Path, content: str) -> bool:
    """Detect if file contains Go template syntax.

    Args:
        filepath: Path to the file.
        content: File content string.

    Returns:
        True if file is a Go template.
    """
    # Check filename
    filename = filepath.name
    if ".tmpl.yaml" in filename or ".template.yaml" in filename:
        return True

    # Check content for {{ }} patterns
    if "{{" in content:
        return True

    return False


def _preprocess_go_template(content: str) -> str:
    """Replace Go template expressions with placeholder values.

    Args:
        content: YAML content with Go templates.

    Returns:
        Content with templates replaced.
    """
    # Replace {{ ... }} with "placeholder-value"
    return re.sub(r"\{\{[^}]+\}\}", "placeholder-value", content)


def _should_exclude_path(filepath: Path, exclude_dirs: Set[str]) -> bool:
    """Check if file path should be excluded.

    Args:
        filepath: Path to check.
        exclude_dirs: Set of directory names to exclude.

    Returns:
        True if path should be excluded.
    """
    # Check if any part of the path matches exclude dirs
    for part in filepath.parts:
        if part in exclude_dirs:
            return True
    return False


def _process_document(
    doc: dict, filepath: Path, resources: LoadedResources
) -> None:
    """Process a single YAML document and categorize it.

    Args:
        doc: Parsed YAML document.
        filepath: Path to the source file.
        resources: LoadedResources to populate.
    """
    if not isinstance(doc, dict):
        return

    kind = doc.get("kind")
    metadata = doc.get("metadata", {})
    name = metadata.get("name")
    namespace = metadata.get("namespace", "default")

    if not kind or not name:
        return

    file_str = str(filepath)

    if kind == "ClusterRole":
        rules = doc.get("rules", [])
        resources.cluster_roles[name] = {
            "rules": rules,
            "file": file_str,
            "doc": doc,
        }

    elif kind == "Role":
        rules = doc.get("rules", [])
        key = f"{namespace}/{name}"
        resources.roles[key] = {
            "rules": rules,
            "file": file_str,
            "doc": doc,
        }

    elif kind == "ClusterRoleBinding":
        resources.cluster_role_bindings.append({
            "doc": doc,
            "file": file_str,
        })

    elif kind == "RoleBinding":
        resources.role_bindings.append({
            "doc": doc,
            "file": file_str,
        })

    elif kind == "ServiceAccount":
        key = f"{namespace}/{name}"
        resources.service_accounts[key] = {
            "file": file_str,
            "doc": doc,
        }

    elif kind == "Pod":
        spec = doc.get("spec", {})
        service_account = spec.get("serviceAccountName", spec.get("serviceAccount", "default"))
        automount_token = spec.get("automountServiceAccountToken", True)

        key = f"{namespace}/{name}"
        resources.pods[key] = {
            "serviceAccount": service_account,
            "file": file_str,
            "automountToken": automount_token,
            "doc": doc,
        }


def _process_file(
    filepath: Path,
    resources: LoadedResources,
    max_file_size: int,
    max_docs_per_file: int,
) -> None:
    """Process a single YAML file.

    Args:
        filepath: Path to YAML file.
        resources: LoadedResources to populate.
        max_file_size: Maximum file size in bytes.
        max_docs_per_file: Maximum documents per file.
    """
    # Check file size
    try:
        file_size = filepath.stat().st_size
        if file_size > max_file_size:
            print(
                f"WARNING: Skipping {filepath} (size {file_size} exceeds limit {max_file_size})",
                file=sys.stderr,
            )
            return
    except OSError as e:
        print(f"WARNING: Could not stat {filepath}: {e}", file=sys.stderr)
        return

    # Read file content
    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        print(f"WARNING: Could not read {filepath}: {e}", file=sys.stderr)
        return

    # Check if Go template and preprocess
    if _is_go_template(filepath, content):
        content = _preprocess_go_template(content)

    # Parse YAML
    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        # Only warn for non-template files
        if not _is_go_template(filepath, content):
            print(f"WARNING: YAML parsing error in {filepath}: {e}", file=sys.stderr)
        return

    # Process documents
    doc_count = 0
    for doc in docs:
        if doc is None:
            continue

        doc_count += 1
        if doc_count > max_docs_per_file:
            print(
                f"WARNING: Stopping processing of {filepath} after {max_docs_per_file} documents",
                file=sys.stderr,
            )
            break

        _process_document(doc, filepath, resources)


def load_manifests(
    paths: List[Union[str, Path]],
    exclude_dirs: Optional[Set[str]] = None,
    use_default_excludes: bool = True,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_docs_per_file: int = DEFAULT_MAX_DOCS_PER_FILE,
) -> LoadedResources:
    """Load Kubernetes manifests from YAML files.

    Args:
        paths: List of file or directory paths to scan.
        exclude_dirs: Additional directories to exclude from scanning.
        use_default_excludes: Whether to use default exclude directories.
        max_file_size: Maximum file size in bytes (default 10MB).
        max_docs_per_file: Maximum documents per file (default 10000).

    Returns:
        LoadedResources containing categorized Kubernetes resources.
    """
    resources = LoadedResources()

    # Build exclude set
    exclude_set: Set[str] = set()
    if use_default_excludes:
        exclude_set.update(DEFAULT_EXCLUDE_DIRS)
    if exclude_dirs:
        exclude_set.update(exclude_dirs)

    # Process each path
    for path in paths:
        path_obj = Path(path)

        if not path_obj.exists():
            print(f"WARNING: Path does not exist: {path}", file=sys.stderr)
            continue

        if path_obj.is_file():
            # Process single file
            if not path_obj.is_symlink():
                _process_file(path_obj, resources, max_file_size, max_docs_per_file)
        else:
            # Scan directory
            for pattern in ["*.yaml", "*.yml"]:
                for filepath in path_obj.rglob(pattern):
                    # Skip symlinks
                    if filepath.is_symlink():
                        continue

                    # Skip excluded directories
                    if _should_exclude_path(filepath, exclude_set):
                        continue

                    # Skip if not a file (shouldn't happen with rglob, but be safe)
                    if not filepath.is_file():
                        continue

                    _process_file(filepath, resources, max_file_size, max_docs_per_file)

    return resources
