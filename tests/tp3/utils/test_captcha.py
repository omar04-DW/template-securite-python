from src.tp3.utils.captcha import Captcha


def test_captcha_init():
    captcha = Captcha("http://example.com/captcha")
    assert captcha.url == "http://example.com/captcha"
    assert captcha.image is None
    assert captcha.value == ""


def test_captcha_get_value():
    captcha = Captcha("http://example.com/captcha")
    captcha.value = "ABC123"
    assert captcha.get_value() == "ABC123"


def test_captcha_solve_without_image():
    captcha = Captcha("http://example.com/captcha")
    captcha.solve()
    assert captcha.value == ""


def test_captcha_capture_no_server():
    captcha = Captcha("http://localhost:99999/captcha")
    captcha.capture()
    assert captcha.image is None
