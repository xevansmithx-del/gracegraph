"""GraceGraph: content-addressed evidence-to-claim compilation."""

from .capsule import compile_capsule, diff_capsules, explain_node, verify_capsule
from .models import COMPILER_VERSION

__all__ = ["compile_capsule", "diff_capsules", "explain_node", "verify_capsule"]
__version__ = COMPILER_VERSION
