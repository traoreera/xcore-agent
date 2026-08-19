"""State machine for `MarketplaceDeploymentRunner` — deliberately separate
from `state.DeploymentState`. The real Marketplace flow has no auth exchange,
no DEK/decrypt step, and loads its install plan from a local operator file
instead of from inside the artifact, so it is a materially different sequence
of security-relevant stages, not a subset of the `.xdeploy` one."""

from enum import Enum


class MarketplaceDeploymentState(str, Enum):
    PENDING = "pending"
    FETCHING = "fetching"
    VERIFYING_SIGNATURE = "verifying_signature"
    EXTRACTING = "extracting"
    LOADING_PLAN = "loading_plan"
    RESOLVING_SEQUENCE = "resolving_sequence"
    INSTALLING = "installing"
    HEALTHCHECKING = "healthchecking"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


MARKETPLACE_TERMINAL_STATES = frozenset(
    {
        MarketplaceDeploymentState.SUCCEEDED,
        MarketplaceDeploymentState.FAILED,
        MarketplaceDeploymentState.ROLLED_BACK,
    }
)

MARKETPLACE_TRANSITIONS: dict[
    MarketplaceDeploymentState, tuple[MarketplaceDeploymentState, ...]
] = {
    MarketplaceDeploymentState.PENDING: (MarketplaceDeploymentState.FETCHING,),
    MarketplaceDeploymentState.FETCHING: (
        MarketplaceDeploymentState.VERIFYING_SIGNATURE,
        MarketplaceDeploymentState.FAILED,
    ),
    MarketplaceDeploymentState.VERIFYING_SIGNATURE: (
        MarketplaceDeploymentState.EXTRACTING,
        MarketplaceDeploymentState.FAILED,
    ),
    MarketplaceDeploymentState.EXTRACTING: (
        MarketplaceDeploymentState.LOADING_PLAN,
        MarketplaceDeploymentState.FAILED,
    ),
    MarketplaceDeploymentState.LOADING_PLAN: (
        MarketplaceDeploymentState.RESOLVING_SEQUENCE,
        MarketplaceDeploymentState.FAILED,
    ),
    MarketplaceDeploymentState.RESOLVING_SEQUENCE: (
        MarketplaceDeploymentState.INSTALLING,
        MarketplaceDeploymentState.FAILED,
    ),
    MarketplaceDeploymentState.INSTALLING: (
        MarketplaceDeploymentState.HEALTHCHECKING,
        MarketplaceDeploymentState.FAILED,
        MarketplaceDeploymentState.ROLLED_BACK,
    ),
    MarketplaceDeploymentState.HEALTHCHECKING: (
        MarketplaceDeploymentState.SUCCEEDED,
        MarketplaceDeploymentState.FAILED,
        MarketplaceDeploymentState.ROLLED_BACK,
    ),
    MarketplaceDeploymentState.SUCCEEDED: (),
    MarketplaceDeploymentState.FAILED: (),
    MarketplaceDeploymentState.ROLLED_BACK: (),
}
