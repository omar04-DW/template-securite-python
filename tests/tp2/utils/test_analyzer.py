from src.tp2.utils.analyzer import ShellcodeAnalyzer


def test_parse_shellcode_hex_format():
    analyzer = ShellcodeAnalyzer("\\x41\\x42\\x43")
    assert analyzer.shellcode_bytes == b"ABC"


def test_parse_shellcode_raw_hex():
    analyzer = ShellcodeAnalyzer("414243")
    assert analyzer.shellcode_bytes == b"ABC"


def test_parse_shellcode_empty():
    analyzer = ShellcodeAnalyzer("")
    assert analyzer.shellcode_bytes == b""


def test_get_shellcode_strings():
    # Shellcode contenant "/bin/sh"
    shellcode = "\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x00\\x90\\x90"
    analyzer = ShellcodeAnalyzer(shellcode)
    strings = analyzer.get_shellcode_strings(min_length=4)
    assert "/bin/sh" in strings


def test_get_shellcode_strings_no_match():
    shellcode = "\\x00\\x01\\x02\\x03"
    analyzer = ShellcodeAnalyzer(shellcode)
    strings = analyzer.get_shellcode_strings(min_length=4)
    assert strings == []


def test_get_capstone_analysis():
    # NOP sled suivi de int 0x80
    shellcode = "\\x90\\x90\\x90\\xcd\\x80"
    analyzer = ShellcodeAnalyzer(shellcode)
    result = analyzer.get_capstone_analysis()
    assert len(result) > 0
    mnemonics = [m for _, m, _ in result]
    assert "nop" in mnemonics


def test_heuristic_analysis_shell():
    shellcode = "\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x00"
    analyzer = ShellcodeAnalyzer(shellcode)
    analyzer.get_shellcode_strings()
    result = analyzer._heuristic_analysis()
    assert "shell" in result.lower()


def test_heuristic_analysis_unknown():
    shellcode = "\\x90\\x90\\x90\\x90"
    analyzer = ShellcodeAnalyzer(shellcode)
    analyzer.get_shellcode_strings()
    result = analyzer._heuristic_analysis()
    assert "inconnu" in result.lower() or "recommandée" in result.lower()


def test_full_analysis():
    shellcode = "\\x90\\x90\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x00"
    analyzer = ShellcodeAnalyzer(shellcode)
    results = analyzer.full_analysis()
    assert "taille" in results
    assert "strings" in results
    assert "pylibemu" in results
    assert "capstone" in results
    assert "llm" in results
    assert results["taille"] == 10


def test_get_pylibemu_analysis():
    shellcode = "\\x90\\x90\\x90"
    analyzer = ShellcodeAnalyzer(shellcode)
    result = analyzer.get_pylibemu_analysis()
    # Soit pylibemu est installé et renvoie un résultat, soit il n'est pas installé
    assert isinstance(result, str)
    assert len(result) > 0


def test_get_llm_analysis():
    shellcode = "\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x00"
    analyzer = ShellcodeAnalyzer(shellcode)
    analyzer.get_shellcode_strings()
    analyzer.get_capstone_analysis()
    result = analyzer.get_llm_analysis()
    assert isinstance(result, str)
    assert "shell" in result.lower() or "Explication" in result
