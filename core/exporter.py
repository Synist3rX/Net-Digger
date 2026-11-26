import json
from datetime import datetime
from pathlib import Path


DEFAULT_OUTPUT_DIR = Path("output")


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


def resolve_output_path(
    raw_output: str,
    domains: list[str],
    default_dir: Path = DEFAULT_OUTPUT_DIR,
) -> Path:
    """
    Resolves the final JSON output path and ensures its parent directory exists.
    - If raw_output is empty (flag '-o' passed without value), builds a filename inside 'output/'.
    - If raw_output has no parent directory (e.g. 'report.json'), places it inside 'output/'.
    - If raw_output includes a directory (e.g. 'custom/report.json'), respects that path.
    """
    cleaned = raw_output.strip()

    if not cleaned:
        if len(domains) == 1:
            safe_domain = domains[0].strip().lower().rstrip(".")
            filename = f"{safe_domain}.json"
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"digger_{timestamp}.json"
        target_path = default_dir / filename
    else:
        candidate = Path(cleaned)
        if cleaned.endswith(("/", "\\")) or candidate.is_dir():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_path = candidate / f"digger_{timestamp}.json"
        elif candidate.parent == Path("."):
            target_path = default_dir / candidate.name
        else:
            target_path = candidate

    target_path.parent.mkdir(parents=True, exist_ok=True)
    return target_path
