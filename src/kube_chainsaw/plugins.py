"""Plugin system for kube-chainsaw."""

import sys
from packaging.version import Version


def load_attack_scenarios(warn_if_missing: bool = False) -> dict:
    """Load attack scenarios from the kube-chainsaw-scenarios plugin package.

    Args:
        warn_if_missing: If True, print warning to stderr when plugin is not installed.

    Returns:
        Dictionary of attack scenarios, or empty dict if plugin not installed or version mismatch.
    """
    try:
        from kube_chainsaw_scenarios import ATTACK_SCENARIOS, MIN_CORE_VERSION
        from importlib.metadata import version as pkg_version

        core_version = pkg_version("kube-chainsaw")
        if Version(core_version) < Version(MIN_CORE_VERSION):
            print(
                f"WARNING: kube-chainsaw-scenarios requires core >={MIN_CORE_VERSION}, "
                f"running {core_version}. Update kube-chainsaw.",
                file=sys.stderr,
            )
            return {}
        return ATTACK_SCENARIOS
    except ImportError:
        if warn_if_missing:
            print(
                "WARNING: Attack scenarios requested but kube-chainsaw-scenarios "
                "is not installed. Install it or remove --include-attack-scenarios.",
                file=sys.stderr,
            )
        return {}
