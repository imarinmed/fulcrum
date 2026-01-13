from ..src.prowler.parser import load_json, load_csv, parse

def test_load_json_list(tmp_path):
    p = tmp_path / "p.json"
    p.write_text('[{"check_id":"c1"}]')
    items = load_json(str(p))
    assert items[0]["check_id"] == "c1"

def test_load_csv(tmp_path):
    p = tmp_path / "p.csv"
    p.write_text("check_id,service,status\nc1,gcs,FAIL\n")
    items = load_csv(str(p))
    assert items[0]["check_id"] == "c1"

def test_parse_mixed(tmp_path):
    j = tmp_path / "j.json"
    c = tmp_path / "c.csv"
    j.write_text('[{"check_id":"j1"}]')
    c.write_text("check_id\nc1\n")
    items = parse([("json", str(j)), ("csv", str(c))])
    assert {i.get("check_id") for i in items} == {"j1","c1"}
