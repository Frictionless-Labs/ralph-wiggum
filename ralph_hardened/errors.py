class RalphError(Exception):
    """Base error for controlled Ralph failures."""


class PreflightError(RalphError):
    """Input, configuration, or environment preflight failed."""


class StateError(RalphError):
    """Canonical state is invalid or an illegal transition was attempted."""


class GitPolicyError(RalphError):
    """A Git isolation or changed-path policy was violated."""


class CheckError(RalphError):
    """A deterministic validation check could not be completed."""
