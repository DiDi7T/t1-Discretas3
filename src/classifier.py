from pyformlang.finite_automaton import DeterministicFiniteAutomaton, State, Symbol

def build_dfa() -> DeterministicFiniteAutomaton:
    dfa = DeterministicFiniteAutomaton()

    # ── Estados ───────────────────────────────────────────────────
    start       = State("Start")
    found_secret = State("FoundSecret")
    needs_review = State("NeedsReview")
    violation   = State("Violation")

    dfa.add_start_state(start)
    dfa.add_final_state(State("Safe"))
    dfa.add_final_state(needs_review)
    dfa.add_final_state(violation)

    # ── Transiciones ──────────────────────────────────────────────
    secrets = ["HARDCODED_PASSWORD", "API_KEY"]
    reviews = ["TODO_COMMENT", "IPv4_ADDRESS", "SUSPICIOUS_URL"]

    for s in secrets:
        dfa.add_transition(start,        Symbol(s), found_secret)
        dfa.add_transition(found_secret, Symbol(s), found_secret)
        dfa.add_transition(needs_review, Symbol(s), found_secret)

    for r in reviews:
        dfa.add_transition(start,        Symbol(r), needs_review)
        dfa.add_transition(needs_review, Symbol(r), needs_review)

    dfa.add_transition(found_secret, Symbol("PRINT_CALL"),  violation)
    dfa.add_transition(start,        Symbol("PRINT_CALL"),  needs_review)
    dfa.add_transition(needs_review, Symbol("PRINT_CALL"),  needs_review)
    dfa.add_transition(violation,    Symbol("PRINT_CALL"),  violation)

    return dfa


def classify(tokens: list[dict]) -> str:
    if not tokens:
        return "Safe"

    dfa = build_dfa()
    labels = [Symbol(t["label"]) for t in tokens]

    current = State("Start")
    for symbol in labels:
        next_states = dfa._transition_function(current, symbol)
        if not next_states:
            break
        current = next(iter(next_states))

    state_name = str(current)

    if state_name == "Violation":
        return "Security Violation"
    elif state_name in ("NeedsReview", "FoundSecret"):  # <- agrega FoundSecret aquí
        return "Needs Review"
    else:
        return "Safe"