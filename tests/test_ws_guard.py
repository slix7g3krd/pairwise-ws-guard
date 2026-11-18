from security.ws_guard import (
    origin_allowed,
    subprotocol_allowed,
    room_allowed,
    frame_ok,
    close_code
)


def test_origin():
    assert origin_allowed('https://app.example', {'https://app.example'}) is True

def test_origin_bad():
    assert origin_allowed('https://evil', {'https://app.example'}) is False

def test_token_url():
    assert origin_allowed('https://app.example?token=x', {'https://app.example'}) is False

def test_proto():
    assert subprotocol_allowed('chat', {'chat'}) is True

def test_proto_bad():
    assert subprotocol_allowed('admin', {'chat'}) is False

def test_room():
    assert room_allowed('r1', 't1', 't1') is True

def test_room_bad():
    assert room_allowed('r1', 't1', 't2') is False

def test_frame():
    assert frame_ok(1024, 4096) is True

def test_frame_big():
    assert frame_ok(8192, 4096) is False

def test_reconnect():
    assert close_code('auth') == 4001

def test_binary():
    assert frame_ok(1024, 4096, binary=True) is False

def test_compress():
    assert frame_ok(1024, 4096, compressed=True) is False

def test_ping():
    assert frame_ok(0, 4096, opcode='ping') is True

def test_empty():
    assert origin_allowed('', {'https://app.example'}) is False

def test_code():
    assert close_code('internal') == 4000
