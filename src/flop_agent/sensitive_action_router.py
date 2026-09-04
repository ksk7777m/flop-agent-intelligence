"""Production boundary for proposed actions originating in remote content.

The router is intentionally capability-poor: every remote proposal is checked
before its concrete sink callable can run.  Classifier output is not consulted.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

from .remote_content_policy import SinkClass, UntrustedRemoteValue, invoke_remote_sink


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

