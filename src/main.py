from detector       import detect
from classifier     import clasificar
from transformation import transformar, describir_fst
from validation import validar, describir_cfg

DEMO_CODE = '''\
password = "admin123"
api_key  = "AKIA1234567890ABCDEF"
print(password)
host = "192.168.1.100"
# TODO: eliminar antes de producción
'''

DEMO_CONFIG = """\
[database] {
    host = localhost;
    password = ${DB_PASSWORD};
}
[api] {
    token = ${API_TOKEN};
    debug = false;
}
"""


def analizar(source_code: str) -> None:
    separator = "=" * 55

    print(separator)
    print("  CHOMSKY — Análisis de seguridad")
    print(separator)

    # ── 1. Detection ─────────────────────────────────────────
    print("\n [Módulo 1] DETECCIÓN (Expresiones Regulares)")
    tokens = detect(source_code)
    if tokens:
        for t in tokens:
            print(f"  línea {t['line']:>3}  [{t['label']}]  →  {t['match']!r}")
    else:
        print("  Sin patrones inseguros detectados.")

    # ── 2. Classification ────────────────────────────────────
    print("\n [Módulo 2] CLASIFICACIÓN (DFA)")
    clasificacion = clasificar(tokens)
    print(f"  Resultado: {clasificacion}")

    # ── 3. Transformation ────────────────────────────────────
    print("\n [Módulo 3] TRANSFORMACIÓN (FST)")
    if clasificacion == "Seguro":
        print("  El código es seguro. No se requiere transformación.")
        return

    result = transformar(source_code, tokens)

    print(f"  Estado final del transductor: {result.estado_final}")
    print(f"\n  Cambios aplicados ({len(result.changes)}):")
    for change in result.changes:
        print(f"    • {change}")

    print("\n  ── Código original ──────────────────────────────")
    for i, line in enumerate(source_code.splitlines(), 1):
        print(f"  {i:>3} │ {line}")

    print("\n  ── Código transformado ──────────────────────────")
    for i, line in enumerate(result.transformed_code.splitlines(), 1):
        print(f"  {i:>3} │ {line}")

    print(f"\n{separator}")

    # ── 4. Validation ────────────────────────────────────────
    print("\n [Módulo 4] VALIDACIÓN (CFG)")
    val_result = validar(DEMO_CONFIG)
    print(f"  Resultado: {'✅ Válido' if val_result.valid else '❌ Inválido'}")
    if val_result.errors:
        for e in val_result.errors:
            print(f"  ✗ {e}")
    if val_result.warnings:
        for w in val_result.warnings:
            print(f"  ⚠ {w}")




if __name__ == "__main__":
    analizar(DEMO_CODE)