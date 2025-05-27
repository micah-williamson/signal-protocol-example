from dataclasses import dataclass
from typing import Optional
from nacl.signing import VerifyKey
from nacl.public import PublicKey
from dataclasses import dataclass


@dataclass
class SessionInitMetadata:
    i_pub_key: VerifyKey
    otpk_pub: PublicKey

@dataclass
class MessageChain:
    chain_key: bytes
    ephemeral_pub: PublicKey
    message_keys: list[bytes]

@dataclass
class EncryptedMessage:
    ord: int
    iv: bytes
    mac: bytes
    ciphertext: bytes
    ephemeral_pub: PublicKey

@dataclass
class ClientEnvelope:
    to: str
    from_: str
    encrypted_message: EncryptedMessage
    session_init_metadata: Optional[SessionInitMetadata]
