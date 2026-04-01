import re

# Estados 
INICIO      = "INICIO"
CON_SECRETO = "CON_SECRETO"   
VIOLACION   = "VIOLACION"     

# tabla de transiciones (estado × símbolo → estado) 
_TRANSITIONS: dict[tuple[str, str], str] = {
    (INICIO,      "HARDCODED_PASSWORD"): CON_SECRETO,
    (INICIO,      "API_KEY"):            CON_SECRETO,
    (INICIO,      "PRINT_CALL"):         INICIO,
    (INICIO,      "TODO_COMMENT"):       INICIO,
    (INICIO,      "IPv4_ADDRESS"):       INICIO,
    (INICIO,      "SUSPICIOUS_URL"):     INICIO,

    (CON_SECRETO, "HARDCODED_PASSWORD"): CON_SECRETO,
    (CON_SECRETO, "API_KEY"):            CON_SECRETO,
    (CON_SECRETO, "PRINT_CALL"):         VIOLACION,
    (CON_SECRETO, "TODO_COMMENT"):       CON_SECRETO,
    (CON_SECRETO, "IPv4_ADDRESS"):       CON_SECRETO,
    (CON_SECRETO, "SUSPICIOUS_URL"):     CON_SECRETO,

    (VIOLACION,   "HARDCODED_PASSWORD"): VIOLACION,
    (VIOLACION,   "API_KEY"):            VIOLACION,
    (VIOLACION,   "PRINT_CALL"):         VIOLACION,
    (VIOLACION,   "TODO_COMMENT"):       VIOLACION,
    (VIOLACION,   "IPv4_ADDRESS"):       VIOLACION,
    (VIOLACION,   "SUSPICIOUS_URL"):     VIOLACION,
}


def _transicion(estado: str, label: str) -> str:
    """Función de transición δ: (Q × Σ) → Q."""
    return _TRANSITIONS.get((estado, label), estado)


def _nombre_envvar(var: str, label: str = "") -> str:
    """
    Convierte el nombre de una variable a UPPER_SNAKE_CASE para usarla
    como nombre de variable de entorno
    Agrega prefijo APP_ para contraseñas
    """
    var = re.sub(r'([a-z])([A-Z])', r'\1_\2', var)
    upper = re.sub(r'[^A-Z0-9]', '_', var.upper()).strip('_')
    if label == "HARDCODED_PASSWORD" and not upper.startswith("APP_"):
        return f"APP_{upper}"
    return upper


class TransformationResult:
    """Resultado del transductor FST."""

    def __init__(
        self,
        transformed_code: str,
        estado_final: str,
        changes: list[str],
        needs_import_os: bool,
    ):
        self.transformed_code = transformed_code
        self.estado_final     = estado_final
        self.changes          = changes
        self.needs_import_os  = needs_import_os

    def __repr__(self) -> str:
        return (
            f"TransformationResult("
            f"estado_final={self.estado_final!r}, "
            f"cambios={len(self.changes)}, "
            f"needs_import_os={self.needs_import_os})"
        )


def transformar(source_code: str, tokens: list[dict]) -> TransformationResult:
    """
    Transductor FST principal.

    Lee tokens en orden de aparición (símbolo de entrada ∈ Σ),
    actualiza el estado con δ y reescribe el código fuente con λ.

    Parámetros
    ----------
    source_code : str
        Código fuente original a transformar.
    tokens : list[dict]
        Salida de detector.detect(). Cada token tiene:
        {"label": str, "match": str, "line": int}

    Retorna
    -------
    TransformationResult
    """
    estado   = INICIO
    changes: list[str] = []
    lines    = source_code.split("\n")
    needs_os = False
    seen_lines: set[int] = set()   

    for token in sorted(tokens, key=lambda t: t["line"]):
        label     = token["label"]
        match_str = token["match"]
        line_no   = token["line"]       
        line_idx  = line_no - 1         

        prev   = estado
        estado = _transicion(estado, label)

        if line_idx >= len(lines) or line_idx in seen_lines:
            continue

        original_line = lines[line_idx]

        # función de salida según símbolo de entrada 

        if label == "HARDCODED_PASSWORD":
            assign_m = re.match(r'([ \t]*)(\w+)\s*=', original_line)
            if assign_m:
                indent   = assign_m.group(1)
                var_name = assign_m.group(2)
                env_name = _nombre_envvar(var_name, label)
                lines[line_idx] = f'{indent}{var_name} = os.getenv("{env_name}")'
                needs_os = True
                seen_lines.add(line_idx)
                changes.append(
                    f'[línea {line_no}] HARDCODED_PASSWORD: '
                    f'`{var_name} = "..."` → `{var_name} = os.getenv("{env_name}")` '
                    f"(δ: {prev} → {estado})"
                )

        elif label == "API_KEY":
            assign_m = re.match(
                r'([ \t]*)(\w+)\s*=\s*["\']?' + re.escape(match_str),
                original_line,
            )
            if assign_m:
                indent   = assign_m.group(1)
                var_name = assign_m.group(2)
                env_name = _nombre_envvar(var_name, label)
                lines[line_idx] = f'{indent}{var_name} = os.getenv("{env_name}")'
                changes.append(
                    f'[línea {line_no}] API_KEY: '
                    f'`{var_name} = "..."` → `{var_name} = os.getenv("{env_name}")` '
                    f"(δ: {prev} → {estado})"
                )
            else:
                
                lines[line_idx] = original_line.replace(
                    match_str, 'os.getenv("API_KEY")', 1
                )
                changes.append(
                    f'[línea {line_no}] API_KEY: valor raw → `os.getenv("API_KEY")` '
                    f"(δ: {prev} → {estado})"
                )
            needs_os = True
            seen_lines.add(line_idx)

        elif label == "PRINT_CALL":
            
            indent_m = re.match(r"([ \t]*)", original_line)
            indent   = indent_m.group(1) if indent_m else ""
            lines[line_idx] = f"{indent}# Sensitive output removed"
            seen_lines.add(line_idx)
            alerta = " [VIOLACIÓN — secreto expuesto]" if estado == VIOLACION else ""
            changes.append(
                f"[línea {line_no}] PRINT_CALL{alerta}: comentado por seguridad "
                f"(δ: {prev} → {estado})"
            )

        

    result = "\n".join(lines)

    
    if needs_os and "import os" not in result:
        result  = "import os\n" + result
        changes = ["[inicio] `import os` agregado automáticamente"] + changes

    return TransformationResult(
        transformed_code=result,
        estado_final=estado,
        changes=changes,
        needs_import_os=needs_os,
    )


def describir_fst() -> str:
    """Retorna la definición formal del FST como string."""
    return (
        "FST — Finite State Transducer (7-tupla)\n"
        "=========================================\n"
        "  Q  = { INICIO, CON_SECRETO, VIOLACION }\n"
        "  Σ  = { HARDCODED_PASSWORD, API_KEY, PRINT_CALL,\n"
        "          TODO_COMMENT, IPv4_ADDRESS, SUSPICIOUS_URL }\n"
        "  Γ  = código Python transformado (strings)\n"
        "  q0 = INICIO\n"
        "  F  = { CON_SECRETO, VIOLACION }\n"
        "  δ  = tabla _TRANSITIONS\n"
        "  λ  = función de salida aplicada por token\n\n"
        "  Reglas de reescritura λ:\n"
        "  ┌──────────────┬────────────────────┬──────────────┬──────────────────────────────────┐\n"
        "  │ Estado       │ Símbolo            │ Estado sig.  │ Salida (Γ)                       │\n"
        "  ├──────────────┼────────────────────┼──────────────┼──────────────────────────────────┤\n"
        "  │ INICIO       │ HARDCODED_PASSWORD │ CON_SECRETO  │ var = os.getenv('APP_VAR')        │\n"
        "  │ INICIO       │ API_KEY            │ CON_SECRETO  │ var = os.getenv('VAR')            │\n"
        "  │ INICIO       │ PRINT_CALL         │ INICIO       │ # Sensitive output removed       │\n"
        "  │ CON_SECRETO  │ HARDCODED_PASSWORD │ CON_SECRETO  │ var = os.getenv('APP_VAR')        │\n"
        "  │ CON_SECRETO  │ API_KEY            │ CON_SECRETO  │ var = os.getenv('VAR')            │\n"
        "  │ CON_SECRETO  │ PRINT_CALL         │ VIOLACION    │ # Sensitive output removed [!]   │\n"
        "  │ VIOLACION    │ PRINT_CALL         │ VIOLACION    │ # Sensitive output removed [!]   │\n"
        "  │ VIOLACION    │ HARDCODED_PASSWORD │ VIOLACION    │ var = os.getenv('APP_VAR')        │\n"
        "  │ *            │ TODO/IPv4/URL      │ mismo        │ pass-through (sin cambio)         │\n"
        "  └──────────────┴────────────────────┴──────────────┴──────────────────────────────────┘\n"
    )