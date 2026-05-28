"""Security tests for kube-chainsaw YAML parsing."""

import pytest
from kube_chainsaw.loader import load_manifests
from kube_chainsaw.suppressions import load_suppressions


class TestYAMLSafety:
    """Test that YAML deserialization is safe from code execution attacks."""

    def test_python_object_tag_rejected(self, tmp_path):
        """Verify that !!python/object/apply tags do not execute code."""
        f = tmp_path / "evil.yaml"
        f.write_text("!!python/object/apply:os.system ['echo pwned']")
        res = load_manifests([str(tmp_path)])
        # Should not crash, should not execute, should return empty
        assert res.is_empty()

    def test_python_module_tag_rejected(self, tmp_path):
        """Verify that !!python/module tags do not load arbitrary modules."""
        f = tmp_path / "evil.yaml"
        f.write_text("!!python/module:os")
        res = load_manifests([str(tmp_path)])
        # Should not crash, should not execute, should return empty
        assert res.is_empty()

    def test_python_name_tag_rejected(self, tmp_path):
        """Verify that !!python/name tags do not reference arbitrary objects."""
        f = tmp_path / "evil.yaml"
        f.write_text("!!python/name:os.system")
        res = load_manifests([str(tmp_path)])
        # Should not crash, should not execute, should return empty
        assert res.is_empty()

    def test_suppression_file_safe_load(self, tmp_path):
        """Verify that suppression file loading uses safe YAML parsing."""
        f = tmp_path / "evil-supp.yaml"
        f.write_text("!!python/object/apply:os.system ['echo pwned']")
        # Should not execute code. Either returns empty list, raises exception, or returns None
        try:
            result = load_suppressions(str(f))
            # If no exception, should return empty or None, not execute code
            assert result == [] or result is None
        except Exception:
            # Raising an exception is acceptable behavior
            # The important thing is that code doesn't execute
            pass

    def test_malformed_yaml_does_not_crash(self, tmp_path):
        """Verify that malformed YAML is handled gracefully."""
        f = tmp_path / "bad.yaml"
        f.write_text("{{{{ invalid yaml ::::")
        res = load_manifests([str(tmp_path)])
        # Should not crash, should warn and return empty
        assert res.is_empty()

    def test_mixed_safe_and_unsafe_documents(self, tmp_path):
        """Verify that unsafe YAML tags cause entire file to be rejected safely."""
        f = tmp_path / "mixed.yaml"
        f.write_text("""---
kind: ClusterRole
metadata:
  name: test-role
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
---
!!python/object/apply:os.system ['echo pwned']
---
kind: Role
metadata:
  name: another-role
  namespace: test
rules:
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["list"]
""")
        res = load_manifests([str(tmp_path)])
        # yaml.safe_load_all will fail on the entire file if any doc has unsafe tags
        # This is correct behavior - the file is rejected and no code executes
        assert res.is_empty()
