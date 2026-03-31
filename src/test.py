from detector import detect
from classifier import classify
# ── Casos de prueba ───────────────────────────────────────────────
cases = [
    {
        "name": "Hardcoded password",
        "code": 'password = "admin123"',
        "expect": ["HARDCODED_PASSWORD"],
    },
    {
        "name": "AWS API Key",
        "code": 'api_key = "AKIA1234567890ABCDEF"',  # 16 chars después de AKIA
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

# ── Ejecutar pruebas ──────────────────────────────────────────────
def run_tests():
    passed = 0
    failed = 0

    print("=" * 50)
    print("        CHOMSKY — Detector Tests")
    print("=" * 50)

    for case in cases:
        tokens = detect(case["code"])
        found_labels = [t["label"] for t in tokens]
        ok = all(e in found_labels for e in case["expect"])

        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"{status}  {case['name']}")
        if not ok:
            print(f"       Expected: {case['expect']}")
            print(f"       Got:      {found_labels}")
            failed += 1
        else:
            passed += 1

    print("=" * 50)
    print(f"Results: {passed} passed, {failed} failed")




def run_classifier_tests():
    cases = [
        {
            "name": "Safe code",
            "tokens": [],
            "expect": "Safe",
        },
        {
            "name": "Solo password → Needs Review",
            "tokens": [{"label": "HARDCODED_PASSWORD"}],
            "expect": "Needs Review",
        },
        {
            "name": "Password + print → Violation",
            "tokens": [{"label": "HARDCODED_PASSWORD"}, {"label": "PRINT_CALL"}],
            "expect": "Security Violation",
        },
        {
            "name": "Solo TODO → Needs Review",
            "tokens": [{"label": "TODO_COMMENT"}],
            "expect": "Needs Review",
        },
    ]

    print("=" * 50)
    print("      CHOMSKY — Classifier Tests")
    print("=" * 50)

    passed = failed = 0
    for case in cases:
        result = classify(case["tokens"])
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
    run_tests()
    print()
    run_classifier_tests()