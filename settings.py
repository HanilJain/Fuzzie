from typing import Optional
from protocol_state import ProtocolStateMachine

conn_loss = False
is_alive = True
retrieving_IP = False
IP_not_alive = False

state_machine: Optional[ProtocolStateMachine] = None