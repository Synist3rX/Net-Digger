import json
from pathlib import Path

def export_to_json(data: dict | list, filepath: str) -> tuple[bool, str]:
    """
    Exports query results to a JSON file robustly.
    """
    try:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

        return True, f"Results successfully exported to: {path.resolve()}"
    except Exception as e:
        return False, f"Error exporting JSON file: {str(e)}"
