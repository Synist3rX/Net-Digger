import json
from unittest.mock import patch
from core.exporter import export_to_json

def test_export_to_json_success(tmp_path):
    # Temporary file using pytest's native fixture
    d = tmp_path / "reports"
    d.mkdir()
    file_path = d / "test_output.json"
    
    test_data = [{"domain": "example.com", "queries": []}]
    
    success, message = export_to_json(test_data, str(file_path))
    
    assert success is True
    assert file_path.exists()
    
    # Verify file content is valid JSON
    with open(file_path, "r", encoding="utf-8") as f:
        loaded_data = json.load(f)
        assert loaded_data == test_data

def test_export_to_json_error():
    # Force an I/O exception using patch to guarantee cross-platform compatibility (Windows/Linux)
    with patch("builtins.open", side_effect=PermissionError("Permission denied")):
        success, message = export_to_json({}, "dummy_path.json")
        
        assert success is False
        assert "Error exporting JSON file" in message
