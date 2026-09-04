"""Production boundary for proposed actions originating in remote content.

The router is intentionally capability-poor: every remote proposal is checked
before its concrete sink callable can run.  Classifier output is not consulted.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
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


@dataclass(frozen=True)
class SensitiveActionRouter:
    """Bind each action class to its real adapter boundary."""

    sinks: Mapping[RemoteAction, Callable[[Any], Any]]

    def dispatch(self, value: UntrustedRemoteValue, action: RemoteAction) -> Any:
        if not isinstance(action, RemoteAction) or action not in self.sinks:
            raise PermissionError("unregistered remote action")
        return invoke_remote_sink(
            value, _ACTION_SINK[action],
            lambda: self.sinks[action](value.value_for_classification_only),
        )


def _new_local_action_boundary(validator: Callable[..., None]) -> Callable[..., Any]:
    def invoke(
        intent: ReviewedLocalIntent, action: LocalActionClass, *, subject: str, target: str,
        payload: str, context: str, revision: str, config_version: str,
        adapter: Callable[[], Any],
    ) -> Any:
        validator(
            intent, action, subject, target=target, payload=payload, context=context,
            revision=revision, config_version=config_version, consume=True)
        return adapter()

    return invoke


_PRODUCTION_LOCAL_BOUNDARY = _new_local_action_boundary(require_local_intent)


def invoke_local_sensitive_action(
    intent: ReviewedLocalIntent, action: LocalActionClass, *, subject: str, target: str,
    payload: str, context: str, revision: str, config_version: str,
    adapter: Callable[[], Any],
) -> Any:
    """The mandatory production boundary shared by all privileged adapters."""
    return _PRODUCTION_LOCAL_BOUNDARY(
        intent, action, subject=subject, target=target, payload=payload, context=context,
        revision=revision, config_version=config_version, adapter=adapter)


def run_subprocess(**kwargs: Any) -> Any:
    return invoke_local_sensitive_action(action=LocalActionClass.SUBPROCESS, **kwargs)


def write_filesystem(**kwargs: Any) -> Any:
    return invoke_local_sensitive_action(action=LocalActionClass.FILESYSTEM_WRITE, **kwargs)


def access_secret(**kwargs: Any) -> Any:
    return invoke_local_sensitive_action(action=LocalActionClass.SECRET_ACCESS, **kwargs)


def invoke_signer(**kwargs: Any) -> Any:
    return invoke_local_sensitive_action(action=LocalActionClass.RECEIPT_SIGN, **kwargs)


def write_presence(**kwargs: Any) -> Any:
    return invoke_local_sensitive_action(action=LocalActionClass.PRESENCE_WRITE, **kwargs)


def invoke_mcp(**kwargs: Any) -> Any:
    return invoke_local_sensitive_action(action=LocalActionClass.MCP_INVOKE, **kwargs)


def use_wallet(**kwargs: Any) -> Any:
    return invoke_local_sensitive_action(action=LocalActionClass.WALLET, **kwargs)


def claim_asset(**kwargs: Any) -> Any:
    return invoke_local_sensitive_action(action=LocalActionClass.CLAIM, **kwargs)


def make_payment(**kwargs: Any) -> Any:
    return invoke_local_sensitive_action(action=LocalActionClass.PAYMENT, **kwargs)
