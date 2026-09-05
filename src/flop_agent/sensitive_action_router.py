"""Production boundary for proposed actions originating in remote content.

The router is intentionally capability-poor: every remote proposal is checked
before its concrete sink callable can run.  Classifier output is not consulted.
"""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class SensitiveActionRouter:
    """Bind each action class to its real adapter boundary."""

    sinks: Mapping[RemoteAction, Callable[[Any], Any]]

    def dispatch(self, value: UntrustedRemoteValue, action: RemoteAction,
                 _guard: Callable[..., Any] = invoke_remote_sink,
                 _action_sinks: Mapping[RemoteAction, SinkClass] = _SEALED_ACTION_SINK,
                 _action_type: type[RemoteAction] = RemoteAction) -> Any:
        if not isinstance(action, _action_type) or action not in self.sinks:
            raise PermissionError("unregistered remote action")
        return _guard(
            value, _action_sinks[action],
            lambda: self.sinks[action](value.value_for_classification_only),
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
