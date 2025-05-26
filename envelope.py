from dataclasses import dataclass
from typing import Optional
from nacl.signing import VerifyKey, SignedMessage
from nacl.public import PublicKey
from dataclasses import dataclass


@dataclass
class SessionInitMetadata:
    i_pub_key: VerifyKey
    ephemeral_pub: PublicKey
    otpk_pub: PublicKey

@dataclass
class EncryptedMessage:
    ord: int
    iv: bytes
    mac: bytes
    ciphertext: bytes

@dataclass
class ClientEnvelope:
    to: str
    from_: str
    encrypted_message: EncryptedMessage
    session_init_metadata: Optional[SessionInitMetadata]
