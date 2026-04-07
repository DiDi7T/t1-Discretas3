from detector       import detect
from classifier     import clasificar
from transformation import transformar, describir_fst
from validation     import validar, describir_cfg
import sys

DEMO_CODE = '''\
password = "admin123"
api_key  = "AKIA1234567890ABCDEF"
print(password)
host = "192.168.1.100"
# TODO: eliminar antes de produccion
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


def analizar(source_code: str, filename: str = "") -> None:
    es_config = filename.endswith(('.env', '.yaml', '.yml'))
    separator = "=" * 55

    print(separator)
    print("  CHOMSKY - Analisis de seguridad")
    print(separator)

    # ── 1. Detection ─────────────────────────────────────────
    print("\n [Modulo 1] DETECCION (Expresiones Regulares)")
    tokens = detect(source_code, filename=filename)
    if tokens:
        for t in tokens:
            print(f"  linea {t['line']:>3}  [{t['label']}]  ->  {t['match']!r}")
    else:
        print("  Sin patrones inseguros detectados.")

    # ── 2. Classification ────────────────────────────────────
    print("\n [Modulo 2] CLASIFICACION (DFA)")
    clasificacion = clasificar(tokens)
    print(f"  Resultado: {clasificacion}")

    # ── 3. Transformation ────────────────────────────────────
    print("\n [Modulo 3] TRANSFORMACION (FST)")
    result = None

    if clasificacion == "Seguro":
        print("  El codigo es seguro. No se requiere transformacion.")
    else:
        result = transformar(source_code, tokens)
        print(f"  Estado final del transductor: {result.estado_final}")
        print(f"\n  Cambios aplicados ({len(result.changes)}):")
        for change in result.changes:
            print(f"    . {change}")
        print("\n  -- Codigo original --")
        for i, line in enumerate(source_code.splitlines(), 1):
            print(f"  {i:>3} | {line}")
        print("\n  -- Codigo transformado --")
        for i, line in enumerate(result.transformed_code.splitlines(), 1):
            print(f"  {i:>3} | {line}")

    print(f"\n{separator}")

    # ── 4. Validation ────────────────────────────────────────
    print("\n [Modulo 4] VALIDACION (CFG)")

    if not es_config:
        print("  Este modulo aplica solo a archivos de configuracion (.env, .yaml)")
        print("  Ejemplo: python main.py archivo.env")
    else:
        print("  -- Archivo original --")
        val_original = validar(source_code, filename=filename)
        print(f"  Resultado: {'Valido' if val_original.valid else 'Invalido'}")
        for e in val_original.errors:
            print(f"  ! {e}")
        for w in val_original.warnings:
            print(f"  ? {w}")

        if not val_original.valid and result is not None:
            print("\n  -- Despues de transformacion --")
            val_transformed = validar(result.transformed_code, filename=filename)
            print(f"  Resultado: {'Valido' if val_transformed.valid else 'Invalido'}")
            for e in val_transformed.errors:
                print(f"  ! {e}")
            for w in val_transformed.warnings:
                print(f"  ? {w}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            contenido = f.read()
        analizar(contenido, filename=sys.argv[1])
    else:
        analizar(DEMO_CODE)