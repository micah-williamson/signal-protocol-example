from dataclasses import dataclass
from typing import Callable
from nacl.signing import VerifyKey, SignedMessage
from nacl.public import PublicKey

from envelope import ClientEnvelope


@dataclass
class ServerIdentity:
    name: str
    i_pub_key: VerifyKey
    pre_pub_key: PublicKey
    pre_signature: SignedMessage
    one_time_pre_keys: list[PublicKey]
    receive_sock: Callable[[ClientEnvelope], None]


class Server:

    _users: dict[str, ServerIdentity]

    def __init__(self):
        self._users = {}
        pass

    def register(self, receive_sock: Callable[[ClientEnvelope], None], name: str, i_pub_key: VerifyKey, 
                 pre_pub_key: PublicKey, pre_signature: SignedMessage, 
                 one_time_pre_keys: list[PublicKey]):
        self._print(f"{name} registered")
        self._users[name] = ServerIdentity(
            name=name,
            i_pub_key=i_pub_key,
            pre_pub_key=pre_pub_key,
            pre_signature=pre_signature,
            one_time_pre_keys=one_time_pre_keys,
            receive_sock=receive_sock
        )
    
    def chat_init(self, recipient: str) -> tuple[VerifyKey, PublicKey, SignedMessage, PublicKey]:
        self._print(f"Chat init requested for {recipient}")
        server_ident = self._users[recipient]
        return (
            server_ident.i_pub_key,
            server_ident.pre_pub_key, 
            server_ident.pre_signature,
            server_ident.one_time_pre_keys.pop()
        )
    
    def send(self, envelope: ClientEnvelope):
        self._print(f"Routing message From {envelope.from_} to {envelope.to}")
        server_ident = self._users[envelope.to]
        server_ident.receive_sock(envelope)
        

    def _print(self, message: str):
        print(f"[Server] {message}")
    
