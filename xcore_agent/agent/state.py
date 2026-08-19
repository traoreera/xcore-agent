from enum import Enum


class DeploymentState(str, Enum):
    PENDING = "pending"
    AUTHENTICATING = "authenticating"
    REQUESTING_ARTIFACT = "requesting_artifact"
    DOWNLOADING = "downloading"
    VERIFYING_SIGNATURE = "verifying_signature"
    OBTAINING_KEY = "obtaining_key"
    DECRYPTING = "decrypting"
    EXTRACTING = "extracting"
    VERIFYING_MANIFEST = "verifying_manifest"
    VALIDATING_PROJECT = "validating_project"
    RESOLVING_PLUGINS = "resolving_plugins"
    RESOLVING_SEQUENCE = "resolving_sequence"
    INSTALLING = "installing"
    HEALTHCHECKING = "healthchecking"
    NOTIFYING = "notifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


TERMINAL_STATES = frozenset(
    {DeploymentState.SUCCEEDED, DeploymentState.FAILED, DeploymentState.ROLLED_BACK}
)

# States reachable from each state, enforced by DeploymentRunner so a bug
# can't silently skip a security-relevant step (e.g. installing before the
# artifact's signature has been verified).
TRANSITIONS: dict[DeploymentState, tuple[DeploymentState, ...]] = {
    DeploymentState.PENDING: (DeploymentState.AUTHENTICATING,),
    DeploymentState.AUTHENTICATING: (
        DeploymentState.REQUESTING_ARTIFACT,
        DeploymentState.FAILED,
    ),
    DeploymentState.REQUESTING_ARTIFACT: (
        DeploymentState.DOWNLOADING,
        DeploymentState.FAILED,
    ),
    DeploymentState.DOWNLOADING: (
        DeploymentState.VERIFYING_SIGNATURE,
        DeploymentState.FAILED,
    ),
    DeploymentState.VERIFYING_SIGNATURE: (
        DeploymentState.OBTAINING_KEY,
        DeploymentState.FAILED,
    ),
    DeploymentState.OBTAINING_KEY: (
        DeploymentState.DECRYPTING,
        DeploymentState.FAILED,
    ),
    DeploymentState.DECRYPTING: (
        DeploymentState.EXTRACTING,
        DeploymentState.FAILED,
    ),
    DeploymentState.EXTRACTING: (
        DeploymentState.VERIFYING_MANIFEST,
        DeploymentState.FAILED,
    ),
    DeploymentState.VERIFYING_MANIFEST: (
        DeploymentState.VALIDATING_PROJECT,
        DeploymentState.FAILED,
    ),
    DeploymentState.VALIDATING_PROJECT: (
        DeploymentState.RESOLVING_PLUGINS,
        DeploymentState.FAILED,
    ),
    DeploymentState.RESOLVING_PLUGINS: (
        DeploymentState.RESOLVING_SEQUENCE,
        DeploymentState.FAILED,
    ),
    DeploymentState.RESOLVING_SEQUENCE: (
        DeploymentState.INSTALLING,
        DeploymentState.FAILED,
    ),
    DeploymentState.INSTALLING: (
        DeploymentState.HEALTHCHECKING,
        DeploymentState.FAILED,
        DeploymentState.ROLLED_BACK,
    ),
    DeploymentState.HEALTHCHECKING: (
        DeploymentState.NOTIFYING,
        DeploymentState.FAILED,
        DeploymentState.ROLLED_BACK,
    ),
    DeploymentState.NOTIFYING: (
        DeploymentState.SUCCEEDED,
        DeploymentState.FAILED,
    ),
    DeploymentState.SUCCEEDED: (),
    DeploymentState.FAILED: (),
    DeploymentState.ROLLED_BACK: (),
}
