from src.tp4.utils.decoder import Decoder


def test_decoder_init():
    decoder = Decoder()
    assert decoder.history == []


def test_decode_base64():
    result = Decoder.decode_base64("SGVsbG8gV29ybGQ=")
    assert result == "Hello World"


def test_decode_base64_invalid():
    result = Decoder.decode_base64("not base64!!!")
    assert result == "not base64!!!"


def test_decode_hex():
    result = Decoder.decode_hex("48656c6c6f")
    assert result == "Hello"


def test_decode_hex_with_prefix():
    result = Decoder.decode_hex("0x48656c6c6f")
    assert result == "Hello"


def test_decode_hex_invalid():
    result = Decoder.decode_hex("xyz")
    assert result == "xyz"


def test_decode_rot13():
    result = Decoder.decode_rot13("Uryyb")
    assert result == "Hello"


def test_decode_binary():
    # "Hi" en binaire
    result = Decoder.decode_binary("0100100001101001")
    assert result == "Hi"


def test_decode_binary_invalid():
    result = Decoder.decode_binary("hello")
    assert result == "hello"


def test_decode_url():
    result = Decoder.decode_url("Hello%20World")
    assert result == "Hello World"


def test_decode_url_no_encoding():
    result = Decoder.decode_url("hello")
    assert result == "hello"


def test_decode_decimal():
    result = Decoder.decode_decimal("72 101 108 108 111")
    assert result == "Hello"


def test_decode_decimal_invalid():
    result = Decoder.decode_decimal("abc")
    assert result == "abc"


def test_decode_auto_base64():
    decoder = Decoder()
    result = decoder.decode("SGVsbG8gV29ybGQ=")
    assert result == "Hello World"


def test_decode_auto_hex():
    decoder = Decoder()
    result = decoder.decode("48656c6c6f")
    assert result == "Hello"


def test_decode_specific():
    decoder = Decoder()
    result = decoder.decode_specific("SGVsbG8=", "base64")
    assert result == "Hello"


def test_decode_specific_unknown():
    decoder = Decoder()
    result = decoder.decode_specific("data", "unknown_encoding")
    assert result == "data"


def test_is_readable():
    assert Decoder._is_readable("Hello World") is True
    assert Decoder._is_readable("") is False
    assert Decoder._is_readable("\x00\x01\x02") is False


def test_decode_reverse():
    result = Decoder.decode_reverse("olleH")
    assert result == "Hello"


def test_decode_base32():
    result = Decoder.decode_base32("JBSWY3DP")
    assert result == "Hello"
