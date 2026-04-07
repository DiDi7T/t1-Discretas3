from pyformlang.finite_automaton import DeterministicFiniteAutomaton, State, Symbol

# ── 1. Estados ────────────────────────────────────────────────
INICIO    = State("Inicio")
SECRETO   = State("Secreto")    # encontró contraseña o API key
REVISAR   = State("Revisar")    # algo sospechoso pero no crítico
VIOLACION = State("Violacion")  # secreto + print → peligro real


# ── 2. Construir el DFA ───────────────────────────────────────

def construir_dfa() -> DeterministicFiniteAutomaton:
    dfa = DeterministicFiniteAutomaton()

    dfa.add_start_state(INICIO)
    dfa.add_final_state(REVISAR)
    dfa.add_final_state(VIOLACION)

    # Desde Inicio
    dfa.add_transition(INICIO, Symbol("HARDCODED_PASSWORD"), SECRETO)
    dfa.add_transition(INICIO, Symbol("API_KEY"),            SECRETO)
    dfa.add_transition(INICIO, Symbol("TODO_COMMENT"),       REVISAR)
    dfa.add_transition(INICIO, Symbol("IPv4_ADDRESS"),       REVISAR)
    dfa.add_transition(INICIO, Symbol("SUSPICIOUS_URL"),     REVISAR)
    dfa.add_transition(INICIO, Symbol("PRINT_CALL"),         REVISAR)
    dfa.add_transition(INICIO,    Symbol("ENV_PLAIN_SECRET"), SECRETO)
    dfa.add_transition(INICIO,    Symbol("YAML_PLAIN_SECRET"), SECRETO)

    # Desde Secreto
    dfa.add_transition(SECRETO, Symbol("HARDCODED_PASSWORD"), SECRETO)
    dfa.add_transition(SECRETO, Symbol("API_KEY"),            SECRETO)
    dfa.add_transition(SECRETO, Symbol("PRINT_CALL"),         VIOLACION)  # ← peligro
    dfa.add_transition(SECRETO,   Symbol("ENV_PLAIN_SECRET"), SECRETO)
    dfa.add_transition(SECRETO,   Symbol("YAML_PLAIN_SECRET"), SECRETO)
    # Desde Revisar
    dfa.add_transition(REVISAR, Symbol("HARDCODED_PASSWORD"), SECRETO)
    dfa.add_transition(REVISAR, Symbol("API_KEY"),            SECRETO)
    dfa.add_transition(REVISAR, Symbol("TODO_COMMENT"),       REVISAR)
    dfa.add_transition(REVISAR, Symbol("IPv4_ADDRESS"),       REVISAR)
    dfa.add_transition(REVISAR, Symbol("SUSPICIOUS_URL"),     REVISAR)
    dfa.add_transition(REVISAR, Symbol("PRINT_CALL"),         REVISAR)
    dfa.add_transition(REVISAR,   Symbol("ENV_PLAIN_SECRET"), SECRETO)
    dfa.add_transition(REVISAR,   Symbol("YAML_PLAIN_SECRET"), SECRETO)

    # Desde Violacion (estado trampa)
    dfa.add_transition(VIOLACION, Symbol("HARDCODED_PASSWORD"), VIOLACION)
    dfa.add_transition(VIOLACION, Symbol("API_KEY"),            VIOLACION)
    dfa.add_transition(VIOLACION, Symbol("PRINT_CALL"),         VIOLACION)
    dfa.add_transition(VIOLACION, Symbol("ENV_PLAIN_SECRET"), VIOLACION)
    dfa.add_transition(VIOLACION, Symbol("YAML_PLAIN_SECRET"), VIOLACION)

    return dfa


# ── 3. Clasificar tokens que vienen del detector ──────────────

def clasificar(tokens: list[dict]) -> str:
    """
    Recibe la lista de tokens que devuelve detect() del detector
    y los recorre con el DFA uno a uno.

    Cada token debe tener al menos la clave "label".
    Retorna: "Seguro", "Necesita Revisión" o "Violación de Seguridad".

    Uso esperado:
        from detector import detect
        from classifier import clasificar

        tokens = detect(codigo_fuente)
        resultado = clasificar(tokens)
    """
    if not tokens:
        return "Seguro"

    dfa           = construir_dfa()
    estado_actual = INICIO

    for token in tokens:
        simbolo    = Symbol(token["label"])
        siguientes = dfa._transition_function(estado_actual, simbolo)

        if not siguientes:
            print(f"  línea {token['line']:>3} [{token['label']}]  →  sin transición, queda en {estado_actual}")
            continue

        estado_actual = next(iter(siguientes))
        print(f"  línea {token['line']:>3} [{token['label']}]  →  {estado_actual}")

    nombre = str(estado_actual)
    if nombre == "Violacion":
        return "Violación de Seguridad"
    elif nombre in ("Secreto", "Revisar"):
        return "Necesita Revisión"
    else:
        return "Seguro"