import re

PATTERNS = {
    "HARDCODED_PASSWORD": r'(?i)password\s*=\s*"[^"]+"',
    "API_KEY":            r'AKIA[0-9A-Z]{16}',
    "IPv4_ADDRESS":       r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "PRINT_CALL":         r'\bprint\s*\(',
    "TODO_COMMENT":       r'#\s*TODO[^\n]*',
    "SUSPICIOUS_URL":     r'https?://(?:localhost|internal|192\.168|10\.\d+)[^\s"\']*',
}

def detect(source_code: str) -> list[dict]:
    results = []
    for label, pattern in PATTERNS.items():
        for match in re.finditer(pattern, source_code):
            line = source_code[:match.start()].count('\n') + 1
            results.append({
                "label": label,
                "match": match.group(),
                "line":  line,
            })
    results.sort(key=lambda x: x["line"])
    return results