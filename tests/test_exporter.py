import json
from unittest.mock import patch
from core.exporter import export_to_json

def test_export_to_json_success(tmp_path):
    """Prueba la exportación correcta de datos estructurados a un archivo JSON."""
    d = tmp_path / "reports"
    d.mkdir()
    file_path = d / "test_output.json"
    
    test_data = [{"domain": "example.com", "queries": []}]
    
    success, message = export_to_json(test_data, str(file_path))
    
    assert success is True
    assert file_path.exists()
    
    with open(file_path, "r", encoding="utf-8") as f:
        loaded_data = json.load(f)
        assert loaded_data == test_data

def test_export_to_json_error():
    """Prueba el manejo robusto de excepciones al fallar la escritura del archivo JSON."""
    with patch("builtins.open", side_effect=PermissionError("Permission denied")):
        success, message = export_to_json({}, "dummy_path.json")
        
        assert success is False
        assert "Error exporting JSON file" in message
