import re

PATTERNS = {
    "HARDCODED_PASSWORD": r'(?i)password\s*=\s*"[^"]+"',
    "API_KEY":            r'AKIA[0-9A-Z]{16}',
    "IPv4_ADDRESS":       r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "PRINT_CALL":         r'\bprint\s*\(',
    "TODO_COMMENT":       r'#\s*TODO[^\n]*',
    "SUSPICIOUS_URL":     r'https?://(?:localhost|internal|192\.168|10\.\d+)[^\s"\']*',
    "ENV_PLAIN_SECRET": r'(?im)^(?:[A-Z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY)[A-Z_]*)=(?!\$\{)[^\s\n]+',
    "YAML_PLAIN_SECRET": r'(?im)^[ \t]*(?:password|secret|token|api_key)[a-z_]*:\s*(?!\$\{)[^\s\n]+',
}

def detect(source_code: str, filename: str = "") -> list[dict]:
    es_env = filename.endswith('.env')
    es_yaml = filename.endswith(('.yaml', '.yml'))
    results = []
    for label, pattern in PATTERNS.items():
        if label == "ENV_PLAIN_SECRET" and not es_env:
            continue
        for match in re.finditer(pattern, source_code):
            line = source_code[:match.start()].count('\n') + 1
            results.append({
                "label": label,
                "match": match.group(),
                "line":  line,
            })
    results.sort(key=lambda x: x["line"])
    return results