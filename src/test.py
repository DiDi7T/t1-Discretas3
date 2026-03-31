from detector import detect
from classifier import clasificar

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


if __name__ == "__main__":
    run_detector_tests()
    print()
    run_classifier_tests()