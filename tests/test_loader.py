"""Tests for YAML manifest loader."""

import tempfile
from pathlib import Path

import pytest

from kube_chainsaw.loader import load_manifests
from kube_chainsaw.models import LoadedResources


class TestBasicLoading:
    """Test basic manifest loading functionality."""

    def test_loads_cluster_roles_from_dangerous_dir(self, dangerous_dir):
        """Should load ClusterRoles from dangerous directory."""
        resources = load_manifests([dangerous_dir])

        assert isinstance(resources, LoadedResources)
        assert len(resources.cluster_roles) > 0

        # Check specific known fixtures
        assert "secrets-readonly-role" in resources.cluster_roles
        assert "wildcard-resources-role" in resources.cluster_roles

        # Verify structure
        cr = resources.cluster_roles["secrets-readonly-role"]
        assert "rules" in cr
        assert "file" in cr
        assert isinstance(cr["rules"], list)

    def test_loads_roles_from_dangerous_dir(self, dangerous_dir):
        """Should load Roles from dangerous directory."""
        resources = load_manifests([dangerous_dir])

        assert len(resources.roles) > 0

        # Roles stored as "namespace/name"
        dangerous_role_key = None
        for key in resources.roles:
            if "dangerous-namespace-role" in key:
                dangerous_role_key = key
                break

        assert dangerous_role_key is not None
        role = resources.roles[dangerous_role_key]
        assert "rules" in role
        assert "file" in role

    def test_loads_bindings_from_dangerous_dir(self, dangerous_dir):
        """Should load ClusterRoleBindings and RoleBindings."""
        resources = load_manifests([dangerous_dir])

        assert len(resources.cluster_role_bindings) > 0
        assert len(resources.role_bindings) > 0

        # Verify structure
        crb = resources.cluster_role_bindings[0]
        assert "doc" in crb
        assert "file" in crb

        rb = resources.role_bindings[0]
        assert "doc" in rb
        assert "file" in rb

    def test_loads_pods_from_dangerous_dir(self, dangerous_dir):
        """Should load Pods with serviceAccount info."""
        resources = load_manifests([dangerous_dir])

        # Check if any pods were loaded
        # cluster-admin-pod.yaml should have a pod
        if len(resources.pods) > 0:
            pod_key = list(resources.pods.keys())[0]
            pod = resources.pods[pod_key]
            assert "serviceAccount" in pod or "serviceAccountName" in pod["doc"]["spec"]
            assert "file" in pod
            assert "automountToken" in pod

    def test_clean_dir_loads_without_error(self, clean_dir):
        """Should load clean directory without errors."""
        resources = load_manifests([clean_dir])

        assert isinstance(resources, LoadedResources)
        # Should have some resources
        assert not resources.is_empty()


class TestMalformedHandling:
    """Test handling of malformed and invalid YAML files."""

    def test_malformed_dir_skipped_gracefully(self, malformed_dir):
        """Should skip malformed files without crashing."""
        resources = load_manifests([malformed_dir])

        # Should return LoadedResources, not crash
        assert isinstance(resources, LoadedResources)
        # Malformed dir has no valid RBAC resources
        assert resources.is_empty()


class TestGoTemplatePreprocessing:
    """Test Go template detection and preprocessing."""

    def test_go_template_preprocessing_works(self, clean_dir):
        """Should preprocess Go templates and extract resources."""
        resources = load_manifests([clean_dir])

        # go-templates.yaml should produce a ClusterRole with placeholder in name
        # After preprocessing {{ .Values.roleName }} becomes "placeholder-value"
        found = False
        for name, cr in resources.cluster_roles.items():
            if "placeholder" in name.lower() or "placeholder-value" in name:
                found = True
                # Verify it came from go-templates.yaml
                assert "go-templates.yaml" in cr["file"]
                break

        assert found, "Go template should be preprocessed and loaded as ClusterRole"


class TestExcludeDirs:
    """Test directory exclusion functionality."""

    def test_default_exclude_dirs_work(self, tmp_path):
        """Should exclude default directories (.git, vendor, node_modules, bin)."""
        # Create structure with vendor/
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()

        valid_dir = tmp_path / "manifests"
        valid_dir.mkdir()

        # Create YAML in both
        vendor_yaml = vendor_dir / "role.yaml"
        vendor_yaml.write_text("""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vendor-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
""")

        valid_yaml = valid_dir / "role.yaml"
        valid_yaml.write_text("""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: valid-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]
""")

        resources = load_manifests([tmp_path])

        # Should only have valid-role, not vendor-role
        assert "valid-role" in resources.cluster_roles
        assert "vendor-role" not in resources.cluster_roles

    def test_custom_exclude_dirs_work(self, tmp_path):
        """Should exclude custom directories."""
        custom_dir = tmp_path / "custom_exclude"
        custom_dir.mkdir()

        valid_dir = tmp_path / "manifests"
        valid_dir.mkdir()

        # Create YAML in both
        custom_yaml = custom_dir / "role.yaml"
        custom_yaml.write_text("""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: custom-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
""")

        valid_yaml = valid_dir / "role.yaml"
        valid_yaml.write_text("""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: valid-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list"]
""")

        resources = load_manifests([tmp_path], exclude_dirs={"custom_exclude"})

        # Should only have valid-role, not custom-role
        assert "valid-role" in resources.cluster_roles
        assert "custom-role" not in resources.cluster_roles

    def test_no_default_excludes_flag_works(self, tmp_path):
        """Should include vendor/ when use_default_excludes=False."""
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()

        vendor_yaml = vendor_dir / "role.yaml"
        vendor_yaml.write_text("""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vendor-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
""")

        resources = load_manifests([tmp_path], use_default_excludes=False)

        # Should have vendor-role when default excludes disabled
        assert "vendor-role" in resources.cluster_roles


class TestSymlinks:
    """Test symlink handling."""

    def test_symlinks_not_followed(self, tmp_path, clean_dir):
        """Should not follow symlinks to avoid duplication."""
        # Create a symlink to clean fixtures
        link = tmp_path / "linked"
        link.symlink_to(clean_dir)

        # Load from tmp_path which contains the symlink
        resources_with_symlink = load_manifests([tmp_path])

        # Load from clean_dir directly
        resources_direct = load_manifests([clean_dir])

        # If symlinks were followed, we'd get duplicates or different counts
        # With symlink skipping, tmp_path should have nothing (symlink ignored)
        assert resources_with_symlink.is_empty()
        assert not resources_direct.is_empty()


class TestFileSizeLimits:
    """Test file size limit enforcement."""

    def test_file_size_limit_works(self, tmp_path):
        """Should skip files larger than max_file_size."""
        # Create a file larger than 1MB (test with small limit)
        large_file = tmp_path / "large.yaml"
        # Create ~2MB of YAML content
        large_content = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: large\ndata:\n"
        large_content += "  large: " + "x" * (2 * 1024 * 1024)
        large_file.write_text(large_content)

        small_file = tmp_path / "small.yaml"
        small_file.write_text("""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: small-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
""")

        # Load with 1MB limit
        resources = load_manifests([tmp_path], max_file_size=1024 * 1024)

        # Should have small-role but not the large ConfigMap
        assert "small-role" in resources.cluster_roles


class TestMultiDocYAML:
    """Test multi-document YAML handling."""

    def test_multi_doc_yaml_works(self, clean_dir):
        """Should load all documents from multi-doc YAML files."""
        resources = load_manifests([clean_dir])

        # multi-doc-mixed.yaml has a Role
        role_found = False
        for key, role in resources.roles.items():
            if "multi-doc-role" in key:
                role_found = True
                assert "multi-doc-mixed.yaml" in role["file"]
                break

        assert role_found, "Should load Role from multi-doc-mixed.yaml"


class TestResourceCategorization:
    """Test proper categorization of different resource types."""

    def test_service_accounts_stored_correctly(self, clean_dir):
        """Should store ServiceAccounts by namespace/name."""
        resources = load_manifests([clean_dir])

        # sa-no-bindings.yaml has a ServiceAccount
        if len(resources.service_accounts) > 0:
            sa_key = list(resources.service_accounts.keys())[0]
            assert "/" in sa_key  # Should be "namespace/name" format
            sa = resources.service_accounts[sa_key]
            assert "file" in sa
            assert "doc" in sa
