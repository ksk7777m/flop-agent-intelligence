"""Production boundary for proposed actions originating in remote content.

The router is intentionally capability-poor: every remote proposal is checked
before its concrete sink callable can run.  Classifier output is not consulted.
"""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .remote_content_policy import (
    LocalActionClass,
    ReviewedLocalIntent,
    SinkClass,
    UntrustedRemoteValue,
    invoke_remote_sink,
    require_local_intent,
)
from .testnet import compatibility_status as _compatibility_status


class RemoteAction(str, Enum):
    HTTP_FOLLOWUP = "HTTP_FOLLOWUP"
    SUBPROCESS = "SUBPROCESS"
    FILESYSTEM_WRITE = "FILESYSTEM_WRITE"
    SECRET_ACCESS = "SECRET_ACCESS"
    SIGN = "SIGN"
    MCP_INVOKE = "MCP_INVOKE"
    WALLET_CONNECT = "WALLET_CONNECT"
    CLAIM = "CLAIM"
    PAYMENT = "PAYMENT"
    NAVIGATE = "NAVIGATE"


_ACTION_SINK: Mapping[RemoteAction, SinkClass] = {
    RemoteAction.HTTP_FOLLOWUP: SinkClass.HTTP_READ_ONLY,
    RemoteAction.SUBPROCESS: SinkClass.SUBPROCESS,
    RemoteAction.FILESYSTEM_WRITE: SinkClass.FILESYSTEM_WRITE,
    RemoteAction.SECRET_ACCESS: SinkClass.SECRET_ACCESS,
    RemoteAction.SIGN: SinkClass.SIGNER,
    RemoteAction.MCP_INVOKE: SinkClass.MCP_INVOCATION,
    RemoteAction.WALLET_CONNECT: SinkClass.WALLET,
    RemoteAction.CLAIM: SinkClass.CLAIM,
    RemoteAction.PAYMENT: SinkClass.PAYMENT,
    RemoteAction.NAVIGATE: SinkClass.PUBLIC_NAVIGATION,
}
_SEALED_ACTION_SINK = MappingProxyType(dict(_ACTION_SINK))


def _build_remote_action_router_type(
    policy_evaluator: Callable[..., Any],
    adapters: Mapping[RemoteAction, Callable[[Any], Any]],
    compatibility_evaluator: Callable[[], Any],
    capability_validator: Callable[..., Any],
    reviewed_source_resolver: Callable[..., Any],
) -> type:
    """Build a router whose authority-bearing dependencies live only in closures."""
    configured_adapters = MappingProxyType(dict(adapters))
    configured_sinks = _SEALED_ACTION_SINK
    action_type = RemoteAction
    # Capture all policy inputs now.  They are deliberately not public call inputs.
    captured_policy = policy_evaluator
    captured_compatibility = compatibility_evaluator
    captured_capability = capability_validator
    captured_source_resolver = reviewed_source_resolver

    class SealedSensitiveActionRouter:
        __slots__ = ()

        def dispatch(self, value: UntrustedRemoteValue, action: RemoteAction) -> Any:
            if not isinstance(action, action_type) or action not in configured_adapters:
                raise PermissionError("unregistered remote action")
            # Keep these dependencies in the sealed service graph even though remote
            # proposals are denied by policy before local capability evaluation.
            _ = (captured_compatibility, captured_capability, captured_source_resolver)
            return captured_policy(
                value, configured_sinks[action],
                lambda: configured_adapters[action](value.value_for_classification_only),
            )

    SealedSensitiveActionRouter.__name__ = "SensitiveActionRouter"
    return SealedSensitiveActionRouter


def _disabled_remote_adapter(_value: Any) -> Any:
    raise PermissionError("remote sensitive action is disabled")


from .remote_content_policy import resolve_reviewed_source  # captured once below

SensitiveActionRouter = _build_remote_action_router_type(
    invoke_remote_sink,
    {action: _disabled_remote_adapter for action in RemoteAction},
    _compatibility_status,
    require_local_intent,
    resolve_reviewed_source,
)


def _build_sensitive_action_service(
    validator: Callable[..., None],
    adapters: Mapping[LocalActionClass, Callable[[], Any]],
) -> Callable[..., Any]:
    """Capture validation and final adapters in one non-replaceable call graph."""
    configured_adapters = MappingProxyType(dict(adapters))

    def invoke(intent: ReviewedLocalIntent, action: LocalActionClass, *, subject: str,
               target: str, payload: str, context: str, revision: str,
               config_version: str) -> Any:
        if action not in configured_adapters:
            raise PermissionError("sensitive action has no sealed production adapter")
        validator(
            intent, action, subject, target=target, payload=payload, context=context,
            revision=revision, config_version=config_version, consume=True)
        return configured_adapters[action]()

    return invoke


def _disabled_adapter() -> Any:
    raise PermissionError("sensitive action is disabled until separately integrated")


_PRODUCTION_ACTION_SERVICE = _build_sensitive_action_service(
    require_local_intent, {action: _disabled_adapter for action in LocalActionClass
                           if action is not LocalActionClass.PRESENCE_NOTE_READ})


def _bind_production_action(action: LocalActionClass,
                            service: Callable[..., Any]) -> Callable[..., Any]:
    def invoke(*, intent: ReviewedLocalIntent, subject: str, target: str, payload: str,
               context: str, revision: str, config_version: str) -> Any:
        return service(
            intent, action, subject=subject, target=target, payload=payload,
            context=context, revision=revision, config_version=config_version)
    return invoke


run_subprocess = _bind_production_action(LocalActionClass.SUBPROCESS, _PRODUCTION_ACTION_SERVICE)
write_filesystem = _bind_production_action(LocalActionClass.FILESYSTEM_WRITE, _PRODUCTION_ACTION_SERVICE)
access_secret = _bind_production_action(LocalActionClass.SECRET_ACCESS, _PRODUCTION_ACTION_SERVICE)
invoke_signer = _bind_production_action(LocalActionClass.RECEIPT_SIGN, _PRODUCTION_ACTION_SERVICE)
write_presence = _bind_production_action(LocalActionClass.PRESENCE_WRITE, _PRODUCTION_ACTION_SERVICE)
invoke_mcp = _bind_production_action(LocalActionClass.MCP_INVOKE, _PRODUCTION_ACTION_SERVICE)
use_wallet = _bind_production_action(LocalActionClass.WALLET, _PRODUCTION_ACTION_SERVICE)
claim_asset = _bind_production_action(LocalActionClass.CLAIM, _PRODUCTION_ACTION_SERVICE)
make_payment = _bind_production_action(LocalActionClass.PAYMENT, _PRODUCTION_ACTION_SERVICE)
