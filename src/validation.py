from textx import metamodel_from_str, TextXSyntaxError
import yaml

# ── Gramática CFG para .env ───────────────────────────────────────────────────
GRAMMAR_ENV = """
Config: entries*=Entry;

Entry: Section | Assignment;

Section:
    '[' name=ID ']'
    '{' entries*=Entry '}'
;

Assignment: key=Key '=' value=Value ';'?;

Key: name=/[A-Za-z_][A-Za-z0-9_]*/;

Value: EnvReference | PlainValue;

EnvReference: '${' name=ID '}';
PlainValue:   value=/[^\n;{}]+/;
"""

# ── Claves sensibles ──────────────────────────────────────────────────────────
SENSITIVE_PATTERNS = {"password", "secret", "token", "api_key", "key"}


def _is_sensitive(key_name: str) -> bool:
    key_lower = key_name.lower()
    return any(pattern in key_lower for pattern in SENSITIVE_PATTERNS)


def _is_env_reference(value) -> bool:
    return hasattr(value, 'name')


def _is_plain_value(value) -> bool:
    return hasattr(value, 'value')


# ── Resultado de validación ───────────────────────────────────────────────────
class ValidationResult:
    def __init__(self, valid: bool, errors: list[str], warnings: list[str]):
        self.valid    = valid
        self.errors   = errors
        self.warnings = warnings

    def __repr__(self) -> str:
        return (
            f"ValidationResult(valid={self.valid}, "
            f"errors={len(self.errors)}, "
            f"warnings={len(self.warnings)})"
        )


# ── Validación semántica .env ─────────────────────────────────────────────────
def _check_assignments(entries, errors: list[str], warnings: list[str]) -> None:
    for entry in entries:
        if hasattr(entry, 'entries'):
            _check_assignments(entry.entries, errors, warnings)
        elif hasattr(entry, 'key') and hasattr(entry, 'value'):
            key_name     = entry.key.name
            value        = entry.value
            is_sensitive = _is_sensitive(key_name)

            if is_sensitive and _is_plain_value(value):
                plain = value.value.strip()
                errors.append(
                    f"Clave sensible '{key_name}' tiene valor plano "
                    f"'{plain}' — debe usar ${{VARIABLE}}"
                )
            elif is_sensitive and _is_env_reference(value):
                pass
            elif not is_sensitive and _is_plain_value(value):
                v = value.value.strip()
                if (len(v) > 8
                        and any(c.isdigit() for c in v)
                        and any(c.isalpha() for c in v)):
                    warnings.append(
                        f"Clave '{key_name}' tiene un valor que podria "
                        f"ser un secreto — considera usar ${{VARIABLE}}"
                    )


# ── Validación semántica YAML ─────────────────────────────────────────────────
def _check_yaml(data, errors: list[str], warnings: list[str], path: str = "") -> None:
    if not isinstance(data, dict):
        return

    for key, value in data.items():
        full_key = f"{path}.{key}" if path else key

        if isinstance(value, dict):
            # Recursivo — sección anidada
            _check_yaml(value, errors, warnings, full_key)
        else:
            val_str = str(value)
            if _is_sensitive(key):
                if val_str.startswith("${") and val_str.endswith("}"):
                    pass  # correcto
                else:
                    errors.append(
                        f"Clave sensible '{full_key}' tiene valor plano "
                        f"'{value}' — debe usar ${{VARIABLE}}"
                    )
            else:
                if (len(val_str) > 8
                        and any(c.isdigit() for c in val_str)
                        and any(c.isalpha() for c in val_str)):
                    warnings.append(
                        f"Clave '{full_key}' podria ser un secreto — "
                        f"considera usar ${{VARIABLE}}"
                    )


# ── Validadores por tipo de archivo ──────────────────────────────────────────
def _validar_env(config_text: str) -> ValidationResult:
    errors   = []
    warnings = []

    try:
        mm    = metamodel_from_str(GRAMMAR_ENV)
        model = mm.model_from_str(config_text)
    except TextXSyntaxError as e:
        return ValidationResult(
            valid=False,
            errors=[f"Error de sintaxis: {e}"],
            warnings=[],
        )

    _check_assignments(model.entries, errors, warnings)

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


def _validar_yaml(config_text: str) -> ValidationResult:
    errors   = []
    warnings = []

    try:
        data = yaml.safe_load(config_text)
    except yaml.YAMLError as e:
        return ValidationResult(
            valid=False,
            errors=[f"Error de sintaxis YAML: {e}"],
            warnings=[],
        )

    if not isinstance(data, dict):
        return ValidationResult(
            valid=False,
            errors=["El archivo YAML debe ser un diccionario de claves y valores"],
            warnings=[],
        )

    _check_yaml(data, errors, warnings)

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


# ── Función principal ─────────────────────────────────────────────────────────
def validar(config_text: str, filename: str = "") -> ValidationResult:
    if filename.endswith(('.yaml', '.yml')):
        return _validar_yaml(config_text)
    else:
        return _validar_env(config_text)


def describir_cfg() -> str:
    return (
        "CFG — Context-Free Grammar (BNF)\n"
        "==================================\n"
        "  Para archivos .env:\n"
        "  Config      -> Entry*\n"
        "  Entry       -> Section | Assignment\n"
        "  Section     -> '[' ID ']' '{' Entry* '}'       <- recursivo\n"
        "  Assignment  -> Key '=' Value ';'?\n"
        "  Key         -> /[A-Za-z_][A-Za-z0-9_]*/\n"
        "  Value       -> EnvReference | PlainValue\n"
        "  EnvReference -> '${' ID '}'\n"
        "  PlainValue  -> /[^\\n;{}]+/\n"
        "\n"
        "  Para archivos .yaml:\n"
        "  Parseado con PyYAML + validacion semantica recursiva\n"
        "  Soporta anidamiento de secciones\n"
        "  Claves sensibles deben usar ${{VARIABLE}}\n"
        "\n"
        "  Por que no es regular:\n"
        "  Las secciones pueden anidarse recursivamente — Section contiene\n"
        "  Entry* que puede contener mas Sections. Eso requiere una pila\n"
        "  para rastrear el anidamiento, lo cual no puede hacer un DFA.\n"
    )