class ProtocolStateMachine:
    """
    Lightweight Wi-Fi runtime state tracker for fuzzing.
    Tracks high-level connectivity state only.
    """

    VALID_TRANSITIONS = {
        ("UNAUTHENTICATED", "auth_success"): "AUTHENTICATED",
        ("AUTHENTICATED", "assoc_success"): "ASSOCIATED",
        ("ASSOCIATED", "connection_established"): "CONNECTED",

        ("AUTHENTICATED", "deauth"): "UNAUTHENTICATED",
        ("ASSOCIATED", "deauth"): "UNAUTHENTICATED",
        ("CONNECTED", "deauth"): "UNAUTHENTICATED",

        ("CONNECTED", "ip_loss"): "DISRUPTED",
        ("ASSOCIATED", "ip_loss"): "DISRUPTED",
        ("AUTHENTICATED", "ip_loss"): "DISRUPTED",
    }

    def __init__(self):
        self.state = "UNAUTHENTICATED"

    def transition(self, event: str):
        key = (self.state, event)

        if key in self.VALID_TRANSITIONS:
            old_state = self.state
            self.state = self.VALID_TRANSITIONS[key]
            print(f"[STATE] {old_state} --({event})--> {self.state}")
        else:
            # Invalid or ignored transition
            print(f"[STATE] Ignored event '{event}' in state '{self.state}'")

    def get_state(self):
        return self.state