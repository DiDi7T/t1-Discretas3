from textx import metamodel_from_str, TextXSyntaxError

# ── Gramática CFG ─────────────────────────────────────────────────────────────
GRAMMAR = """
Config: entries*=Entry;

Entry: Section | Assignment;

Section:
    '[' name=ID ']'
    '{' entries*=Entry '}'
;

Assignment: key=Key '=' value=Value ';';

Key: SensitiveKey | RegularKey;

SensitiveKey: name=/password|secret|token|api_key|key/;
RegularKey:   name=ID;

Value: EnvReference | SafeString | UnsafeString;

EnvReference: '${' name=ID '}';
SafeString:   value=/[a-zA-Z0-9_.\\-]+/;
UnsafeString: value=/".+?"/;
"""

# ── Claves sensibles ──────────────────────────────────────────────────────────
SENSITIVE_KEYS = {"password", "secret", "token", "api_key", "key"}

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


def _check_assignments(entries, errors: list[str], warnings: list[str]) -> None:
    """
    Recorre recursivamente los entries y verifica:
    - Claves sensibles deben usar EnvReference (${VAR})
    - Claves normales no deberían tener valores que parezcan secretos
    """
    for entry in entries:
        # Si es una sección, revisar sus entries recursivamente
        if hasattr(entry, 'entries'):
            _check_assignments(entry.entries, errors, warnings)

        # Si es un assignment
        elif hasattr(entry, 'key') and hasattr(entry, 'value'):
            key_name = entry.key.name.lower()
            value    = entry.value

            is_sensitive = key_name in SENSITIVE_KEYS

            # Clave sensible con valor plano → error
            if is_sensitive and hasattr(value, 'value'):
                errors.append(
                    f"Clave sensible '{key_name}' tiene valor plano "
                    f"'{value.value}' — debe usar ${{VARIABLE}}"
                )

            # Clave sensible con EnvReference → OK
            elif is_sensitive and hasattr(value, 'name'):
                pass  # correcto

            # Clave normal con valor que parece secreto → warning
            elif not is_sensitive and hasattr(value, 'value'):
                v = str(value.value).strip('"')
                if len(v) > 8 and any(c.isdigit() for c in v) and any(c.isalpha() for c in v):
                    warnings.append(
                        f"Clave '{key_name}' tiene un valor que podría ser un secreto — "
                        f"considera usar ${{VARIABLE}}"
                    )


def validar(config_text: str) -> ValidationResult:
    """
    Valida un archivo de configuración contra la gramática CFG.

    Parámetros
    ----------
    config_text : str
        Contenido del archivo de configuración.

    Retorna
    -------
    ValidationResult con valid, errors y warnings.
    """
    errors   = []
    warnings = []

    # 1. Validar sintaxis con la gramática CFG
    try:
        mm    = metamodel_from_str(GRAMMAR)
        model = mm.model_from_str(config_text)
    except TextXSyntaxError as e:
        return ValidationResult(
            valid=False,
            errors=[f"Error de sintaxis: {e}"],
            warnings=[],
        )

    # 2. Validar semántica — claves sensibles deben usar EnvReference
    _check_assignments(model.entries, errors, warnings)

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


def describir_cfg() -> str:
    """Retorna la definición formal de la gramática."""
    return (
        "CFG — Context-Free Grammar (BNF)\n"
        "==================================\n"
        "  Config      → Entry*\n"
        "  Entry       → Section | Assignment\n"
        "  Section     → '[' ID ']' '{' Entry* '}'       ← recursivo\n"
        "  Assignment  → Key '=' Value ';'\n"
        "  Key         → SensitiveKey | RegularKey\n"
        "  SensitiveKey → password|secret|token|api_key|key\n"
        "  RegularKey  → ID\n"
        "  Value       → EnvReference | SafeString | UnsafeString\n"
        "  EnvReference → '${' ID '}'\n"
        "\n"
        "  Por qué no es regular:\n"
        "  Las secciones pueden anidarse recursivamente — Section contiene\n"
        "  Entry* que puede contener más Sections. Eso requiere una pila\n"
        "  para rastrear el anidamiento, lo cual no puede hacer un DFA.\n"
    )