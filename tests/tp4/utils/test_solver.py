from src.tp4.utils.solver import Solver


def test_solver_init():
    solver = Solver("127.0.0.1", 9999)
    assert solver.host == "127.0.0.1"
    assert solver.port == 9999
    assert solver.flag == ""
    assert solver.connection is None


def test_solver_get_flag():
    solver = Solver("127.0.0.1", 9999)
    solver.flag = "flag{test}"
    assert solver.get_flag() == "flag{test}"


def test_solver_close_no_connection():
    solver = Solver("127.0.0.1", 9999)
    solver.close()
    # Doit pas crasher sans connexion


def test_solver_connect_bad_host():
    solver = Solver("127.0.0.1", 1)
    result = solver.connect()
    assert result is False


def test_extract_challenge():
    solver = Solver("127.0.0.1", 9999)
    assert solver._extract_challenge("Decode: SGVsbG8=") == "SGVsbG8="
    assert solver._extract_challenge("Challenge: 48656c6c6f") == "48656c6c6f"
    assert solver._extract_challenge("Data: test123") == "test123"
