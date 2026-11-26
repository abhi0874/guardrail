from pathlib import Path

from jsonschema import Draft202012Validator
from scanner_api.schemas import encoded, schemas


def test_schema_files_generated_from_models():
    for name, schema in schemas().items():
        Draft202012Validator.check_schema(schema)
        path = Path("api/schemas/v1") / (name + ".json")
        assert path.read_bytes() == encoded(schema)
