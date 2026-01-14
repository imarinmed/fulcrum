from src.core.markdown import escape, table, header, format_number


def test_escape_specials():
    s = escape("a|b*c_d[e]`f\\g\nh")
    assert "\\|" in s
    assert "\\*" in s
    assert "\\_" in s
    assert "\\[" in s and "\\]" in s
    assert "\\`" in s
    assert "\\\\" in s
    assert "<br/>" in s


def test_table_alignment_and_columns():
    md = table(["a", "b"], [["1", "2"], ["3", "4"]], ["left", "right"])
    lines = md.strip().split("\n")
    assert lines[0].startswith("| a | b |")
    assert ":---" in lines[1] and "---:" in lines[1]
    assert lines[2].count("|") == lines[0].count("|")


def test_header_levels():
    h2 = header(2, "Title")
    assert h2.startswith("## ")


def test_format_number_units():
    assert format_number(1536, "bytes").endswith("KB")
    assert "%" in format_number(12.345, "percent")
    assert "," in format_number(12345, "count")
