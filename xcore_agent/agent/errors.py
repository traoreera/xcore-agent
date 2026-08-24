class DeploymentError(Exception):
    """Base class for all fatal deployment pipeline errors."""


class AuthenticationError(DeploymentError):
    """Authentication against XCore Hub failed."""


class ArtifactError(DeploymentError):
    """Artifact could not be requested, downloaded, verified, or decrypted."""


class PublishError(DeploymentError):
    """A built artifact could not be uploaded to XCore Hub."""


class InstallError(DeploymentError):
    """A filesystem-level install step failed."""


class HealthcheckError(DeploymentError):
    """A plugin or project failed its post-install healthcheck."""
