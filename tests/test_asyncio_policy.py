import backend.asyncio_policy as policy


class FakeLoop:
    def __init__(self):
        self.handler = None
        self.default_contexts = []

    def get_exception_handler(self):
        return None

    def set_exception_handler(self, handler):
        self.handler = handler

    def default_exception_handler(self, context):
        self.default_contexts.append(context)


def reset_error(winerror=10054):
    error = ConnectionResetError("client reset")
    error.winerror = winerror
    return error


def test_matches_only_proactor_connection_lost_winerror_10054():
    expected = {"message": policy.PROACTOR_CONNECTION_LOST + "()", "exception": reset_error()}
    assert policy.is_expected_windows_client_disconnect(expected)
    assert not policy.is_expected_windows_client_disconnect({**expected, "exception": reset_error(10053)})
    assert not policy.is_expected_windows_client_disconnect({**expected, "message": "Unhandled API task"})
    assert not policy.is_expected_windows_client_disconnect({**expected, "exception": RuntimeError("boom")})


def test_windows_handler_suppresses_expected_disconnect_only(monkeypatch):
    loop = FakeLoop()
    monkeypatch.setattr(policy.os, "name", "nt")
    policy.install_windows_disconnect_handler(loop)
    expected = {"message": policy.PROACTOR_CONNECTION_LOST + "()", "exception": reset_error()}
    unexpected = {"message": "API failed", "exception": RuntimeError("boom")}

    loop.handler(loop, expected)
    loop.handler(loop, unexpected)

    assert loop.default_contexts == [unexpected]


def test_non_windows_loop_is_not_modified(monkeypatch):
    loop = FakeLoop()
    monkeypatch.setattr(policy.os, "name", "posix")
    assert policy.install_windows_disconnect_handler(loop) is None
    assert loop.handler is None
