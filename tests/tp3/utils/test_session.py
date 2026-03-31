from src.tp3.utils.session import Session


def test_session_init():
    session = Session("http://example.com/captcha")
    assert session.url == "http://example.com/captcha"
    assert session.captcha_value == ""
    assert session.flag_value == ""
    assert session.valid_flag == ""


def test_session_get_flag():
    session = Session("http://example.com/captcha")
    session.valid_flag = "flag{test123}"
    assert session.get_flag() == "flag{test123}"


def test_submit_request_no_crash():
    session = Session("http://localhost:99999/captcha")
    session.submit_request()
    # Doit pas crasher même sans serveur


def test_process_response_none():
    session = Session("http://example.com/captcha")
    result = session.process_response()
    assert result is False
