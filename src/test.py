from detector import detect
from classifier import clasificar
from transformation import transformar
from validation import validar


# ── Casos de prueba del detector ──────────────────────────────────
detector_cases = [
    {
        "name": "Hardcoded password",
        "code": 'password = "admin123"',
        "expect": ["HARDCODED_PASSWORD"],
    },
    {
        "name": "AWS API Key",
        "code": 'api_key = "AKIA1234567890ABCDEF"',
        "expect": ["API_KEY"],
    },
    {
        "name": "Print sensitive variable",
        "code": 'print(password)',
        "expect": ["PRINT_CALL"],
    },
    {
        "name": "IPv4 exposed",
        "code": 'host = "192.168.0.1"',
        "expect": ["IPv4_ADDRESS"],
    },
    {
        "name": "Safe code",
        "code": 'x = 42',
        "expect": [],
    },
    {
        "name": "Multiple violations",
        "code": 'password = "admin123"\nprint(password)',
        "expect": ["HARDCODED_PASSWORD", "PRINT_CALL"],
    },
]

# ── Casos de prueba del clasificador ─────────────────────────────
classifier_cases = [
    {
        "name": "Sin tokens → Seguro",
        "tokens": [],
        "expect": "Seguro",
    },
    {
        "name": "Solo password → Necesita Revisión",
        "tokens": [{"label": "HARDCODED_PASSWORD", "line": 1}],
        "expect": "Necesita Revisión",
    },
    {
        "name": "Password + print → Violación de Seguridad",
        "tokens": [
            {"label": "HARDCODED_PASSWORD", "line": 1},
            {"label": "PRINT_CALL",         "line": 2},
        ],
        "expect": "Violación de Seguridad",
    },
    {
        "name": "Solo TODO → Necesita Revisión",
        "tokens": [{"label": "TODO_COMMENT", "line": 1}],
        "expect": "Necesita Revisión",
    },
    {
        "name": "API key + print → Violación de Seguridad",
        "tokens": [
            {"label": "API_KEY",    "line": 1},
            {"label": "PRINT_CALL", "line": 2},
        ],
        "expect": "Violación de Seguridad",
    },
    {
        "name": "URL sospechosa → Necesita Revisión",
        "tokens": [{"label": "SUSPICIOUS_URL", "line": 1}],
        "expect": "Necesita Revisión",
    },
    {
        "name": "IPv4 + TODO → Necesita Revisión",
        "tokens": [
            {"label": "IPv4_ADDRESS", "line": 1},
            {"label": "TODO_COMMENT", "line": 2},
        ],
        "expect": "Necesita Revisión",
    },
    {
        "name": "Violación se mantiene con más tokens",
        "tokens": [
            {"label": "API_KEY",            "line": 1},
            {"label": "PRINT_CALL",         "line": 2},
            {"label": "HARDCODED_PASSWORD", "line": 3},
        ],
        "expect": "Violación de Seguridad",
    },
]


# ── Ejecutar pruebas del detector ─────────────────────────────────
def run_detector_tests():
    passed = failed = 0

    print("=" * 50)
    print("        CHOMSKY — Detector Tests")
    print("=" * 50)

    for case in detector_cases:
        tokens = detect(case["code"])
        found_labels = [t["label"] for t in tokens]
        ok = all(e in found_labels for e in case["expect"])

        print(f"{'✅ PASS' if ok else '❌ FAIL'}  {case['name']}")
        if not ok:
            print(f"       Expected: {case['expect']}")
            print(f"       Got:      {found_labels}")
            failed += 1
        else:
            passed += 1

    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")


# ── Ejecutar pruebas del clasificador ────────────────────────────
def run_classifier_tests():
    passed = failed = 0

    print("=" * 50)
    print("      CHOMSKY — Classifier Tests")
    print("=" * 50)

    for case in classifier_cases:
        result = clasificar(case["tokens"])
        ok = result == case["expect"]

        print(f"{'✅ PASS' if ok else '❌ FAIL'}  {case['name']}")
        if not ok:
            print(f"       Expected: {case['expect']}")
            print(f"       Got:      {result}")
            failed += 1
        else:
            passed += 1

    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")



# ── Casos de prueba del transductor ──────────────────────────────────
transformation_cases = [
    {
        "name": "Password hardcodeado → os.getenv",
        "code": 'password = "admin123"',
        "expect_in":     ['os.getenv("APP_PASSWORD")', "import os"],
        "expect_not_in": ['"admin123"'],
        "expect_state":  "CON_SECRETO",
    },
    {
        "name": "API key → os.getenv",
        "code": 'api_key = "AKIA1234567890ABCDEF"',
        "expect_in":     ["os.getenv", "import os"],
        "expect_not_in": ["AKIA1234567890ABCDEF"],
        "expect_state":  "CON_SECRETO",
    },
    {
        "name": "Print solo → comentado",
        "code": "print(password)",
        "expect_in":     ["# Sensitive output removed"],
        "expect_not_in": ["print(password)"],
        "expect_state":  "INICIO",
    },
    {
        "name": "Password + print → transformación completa (Violación)",
        "code": 'password = "admin123"\nprint(password)',
        "expect_in":     ["os.getenv", "# Sensitive output removed", "import os"],
        "expect_not_in": ['"admin123"', "print(password)"],
        "expect_state":  "VIOLACION",
    },
    {
        "name": "API key + print → violación con transformación",
        "code": 'api_key = "AKIA1234567890ABCDEF"\nprint(api_key)',
        "expect_in":     ["os.getenv", "# Sensitive output removed", "import os"],
        "expect_not_in": ["AKIA1234567890ABCDEF", "print(api_key)"],
        "expect_state":  "VIOLACION",
    },
    {
        "name": "Código seguro → sin cambios",
        "code": "x = 42",
        "expect_in":     ["x = 42"],
        "expect_not_in": ["import os"],
        "expect_state":  "INICIO",
    },
    {
        "name": "import os no duplicado si ya existe",
        "code": "import os\nx = 42",
        "expect_in":     ["import os"],
        "expect_not_in": ["import os\nimport os"],
        "expect_state":  "INICIO",
    },
    {
        "name": "Indentación preservada en print comentado",
        "code": 'password = "secret"\n    print(password)',
        "expect_in":     ["    # Sensitive output removed"],
        "expect_not_in": ["print(password)"],
        "expect_state":  "VIOLACION",
    },
]


# ── Ejecutar pruebas del transductor ─────────────────────────────────
def run_transformation_tests():
    passed = failed = 0

    print("=" * 50)
    print("    CHOMSKY — Transformation Tests (FST)")
    print("=" * 50)

    for case in transformation_cases:
        tokens  = detect(case["code"])
        result  = transformar(case["code"], tokens)
        output  = result.transformed_code

        ok_in     = all(e in output for e in case["expect_in"])
        ok_not_in = all(e not in output for e in case["expect_not_in"])
        ok_state  = result.estado_final == case["expect_state"]
        ok        = ok_in and ok_not_in and ok_state

        print(f"{' PASS' if ok else ' FAIL'}  {case['name']}")
        if not ok:
            if not ok_in:
                missing = [e for e in case["expect_in"] if e not in output]
                print(f"       Falta en salida:  {missing}")
            if not ok_not_in:
                present = [e for e in case["expect_not_in"] if e in output]
                print(f"       No debería estar: {present}")
            if not ok_state:
                print(f"       Estado esperado: {case['expect_state']}")
                print(f"       Estado obtenido: {result.estado_final}")
            failed += 1
        else:
            passed += 1

    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")


 





def run_validation_tests():
    cases = [
        {
            "name": "Config segura con EnvReference",
            "config": 'password = ${APP_PASSWORD};\nhost = localhost;',
            "expect_valid": True,
            "expect_errors": 0,
        },
        {
            "name": "Config insegura — password plano",
            "config": 'password = "admin123";',
            "expect_valid": False,
            "expect_errors": 1,
        },
        {
            "name": "Sección anidada segura",
            "config": '[database] { password = ${DB_PASSWORD}; host = localhost; }',
            "expect_valid": True,
            "expect_errors": 0,
        },
        {
            "name": "Sección anidada insegura",
            "config": '[database] { password = "admin123"; }',
            "expect_valid": False,
            "expect_errors": 1,
        },
        {
            "name": "Sintaxis inválida",
            "config": 'password ${APP_PASSWORD}',  # falta el =
            "expect_valid": False,
            "expect_errors": 1,
        },
    ]

    print("=" * 50)
    print("     CHOMSKY — Validation Tests (CFG)")
    print("=" * 50)

    passed = failed = 0
    for case in cases:
        result = validar(case["config"])
        ok = (
            result.valid == case["expect_valid"] and
            len(result.errors) == case["expect_errors"]
        )
        print(f"{' PASS' if ok else ' FAIL'}  {case['name']}")
        if not ok:
            print(f"       Valid esperado: {case['expect_valid']} → got {result.valid}")
            print(f"       Errores esperados: {case['expect_errors']} → got {len(result.errors)}")
            if result.errors:
                for e in result.errors:
                    print(f"       ⚠ {e}")
            failed += 1
        else:
            passed += 1

    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")
    
if __name__ == "__main__":
    run_detector_tests()
    print()
    run_classifier_tests()
    print()
    run_transformation_tests()
    print()
    run_validation_tests()
    print()