import asyncio
import logging
import os
from collections.abc import Callable
from typing import Any


log = logging.getLogger("smu.web.transport")
PROACTOR_CONNECTION_LOST = "Exception in callback _ProactorBasePipeTransport._call_connection_lost"


def is_expected_windows_client_disconnect(context: dict[str, Any]) -> bool:
    """Match only Windows' harmless reset while Proactor closes a client socket."""
    exception = context.get("exception")
    message = str(context.get("message", ""))
    return (
        isinstance(exception, ConnectionResetError)
        and getattr(exception, "winerror", None) == 10054
        and message.startswith(PROACTOR_CONNECTION_LOST)
    )


def install_windows_disconnect_handler(
    loop: asyncio.AbstractEventLoop,
) -> Callable[[asyncio.AbstractEventLoop, dict[str, Any]], None] | None:
    """Suppress only the known Proactor client-disconnect callback on Windows."""
    previous = loop.get_exception_handler()
    if os.name != "nt":
        return previous

    def handle(current_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        if is_expected_windows_client_disconnect(context):
            log.debug("Windows client disconnected during Proactor transport close winerror=10054")
            return
        if previous is not None:
            previous(current_loop, context)
        else:
            current_loop.default_exception_handler(context)

    loop.set_exception_handler(handle)
    return previous
