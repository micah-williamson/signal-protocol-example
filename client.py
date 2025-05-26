from dataclasses import dataclass
from hmac import HMAC
import os
from typing import Optional
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from nacl.public import PrivateKey, PublicKey
from nacl.bindings import crypto_scalarmult
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend

from envelope import ClientEnvelope, EncryptedMessage, SessionInitMetadata
from server import Server

@dataclass
class ClientContact:
    name: str
    root_key: bytes
    chain_key: bytes
    message_keys: list[bytes]
    # Client confirmed has initiated e2ee. While FALSE messages will send with init metadata
    confirmed: bool
    # Initiator fields. These values only exist if WE initiated the chat.
    session_init_metadata: Optional[SessionInitMetadata] = None

@dataclass
class Client:

    _name: str

    # Identity
    _i_priv_key: SigningKey
    _i_pub_key: VerifyKey

    _signed_pre_key: tuple[PrivateKey, PublicKey, SignedMessage]
    _one_time_pre_keys: list[tuple[PrivateKey, PublicKey]]
    _server: Server

    _contacts: dict[str, ClientContact]

    def __init__(self, name: str):
        self._name = name
        (
            self._i_priv_key, 
            self._i_pub_key
        ) = self._gen_identity()
        self._signed_pre_key = self._gen_signed_pre_key(self._i_priv_key)
        self._one_time_pre_keys = self._gen_one_time_pre_keys()
        self._contacts = {}

    def connect(self, server: Server):
        self._server = server
        server.register(self.receive, self._name, self._i_pub_key, self._signed_pre_key[1], 
                        self._signed_pre_key[2], [otpk[1] for otpk in self._one_time_pre_keys])
        
    def send(self, recipient: str, message: bytes):
        if recipient not in self._contacts:
            self._init_session_as_initiator(recipient)

        self._print(f"Sending message [to {recipient}]: {message}")
        contact = self._contacts[recipient]

        session_init_metadata = None
        if not contact.confirmed:
            self._print(f"Sending session init metadata")
            session_init_metadata = contact.session_init_metadata

        encrypted_message = self._do_encrypt_and_ratchet(message, contact)
        envelope = ClientEnvelope(
            to=recipient,
            from_=self._name,
            encrypted_message=encrypted_message,
            session_init_metadata=session_init_metadata
        )
        self._server.send(envelope)

    def receive(self, envelope: ClientEnvelope):
        self._print(f"Received message from {envelope.from_}")

        if envelope.from_ not in self._contacts:
            self._print(f"New contact. Initializing session")
            sim = envelope.session_init_metadata
            assert sim is not None
            self._init_session_as_recipient(envelope.from_, sim)
        
        contact = self._contacts[envelope.from_]
        encrypted_message = envelope.encrypted_message
        
        # TODO: Verify hmac

        # Ratchet chain key until we have the message keys we need
        while len(contact.message_keys) <= encrypted_message.ord:
            contact.message_keys.append(self._get_message_key(contact.chain_key))
            contact.chain_key = self._ratchet(contact.chain_key)
        
        message_key = contact.message_keys[encrypted_message.ord]
        
        # Decrypt with message 
        decrypted_message_text = self._decrypt_message(message_key, encrypted_message)
        
        self._print(f"Got decrypted message: {decrypted_message_text}")                   

    def _init_session_as_recipient(self, initiator: str, sim: SessionInitMetadata):
        self._print(f"Initializing chat session with {initiator} as recipient")
        i_priv_key = self._i_priv_key.to_curve25519_private_key()
        s_i_pub_key = sim.i_pub_key.to_curve25519_public_key()
        pre_key_priv = self._signed_pre_key[0]

        otpk_priv = [otpk[0] for otpk in self._one_time_pre_keys if otpk[1] == sim.otpk_pub][0]
        dh1 = crypto_scalarmult(pre_key_priv.encode(), s_i_pub_key.encode())
        dh2 = crypto_scalarmult(i_priv_key.encode(), sim.ephemeral_pub.encode())
        dh3 = crypto_scalarmult(pre_key_priv.encode(), sim.ephemeral_pub.encode())
        dh4 = crypto_scalarmult(otpk_priv.encode(), sim.ephemeral_pub.encode())
        master_secret = dh1 + dh2 + dh3 + dh4

        # Generate session keys
        deriver = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            info=b"WhisperText",
            salt=b'\x00' * 32
        )
        root_and_chain = deriver.derive(master_secret)
        root_key = root_and_chain[:32]
        chain_key = root_and_chain[32:]

        self._print(f"Generated master secret: {master_secret}")
        self._print(f"Generated Root Key: {root_key}")
        self._print(f"Generated Chain Key: {chain_key}")

        self._contacts[initiator] = ClientContact(
            name=initiator,
            root_key=root_key,
            chain_key=chain_key,
            message_keys=[],
            confirmed=True
        )
    
    def _init_session_as_initiator(self, recipient: str):
        self._print(f"Initializing chat session with {recipient} as initiator")
        (i_pub_key, pub_pre_key, pub_pre_sig, otpk) = self._server.chat_init(recipient)

        if not i_pub_key.verify(pub_pre_key.encode(), pub_pre_sig.signature):
            raise Exception("Pre key signature invalid")
        
        self._print("Pre key signature verified")

        # Generate master secret
        ephemeral_key = PrivateKey.generate()
        dh1 = crypto_scalarmult(self._i_priv_key.to_curve25519_private_key().encode(), pub_pre_key.encode())
        dh2 = crypto_scalarmult(ephemeral_key.encode(), i_pub_key.to_curve25519_public_key().encode())
        dh3 = crypto_scalarmult(ephemeral_key.encode(), pub_pre_key.encode())
        dh4 = crypto_scalarmult(ephemeral_key.encode(), otpk.encode())
        master_secret = dh1 + dh2 + dh3 + dh4

        # Generate session keys
        deriver = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            info=b"WhisperText",
            salt=b'\x00' * 32
        )
        root_and_chain = deriver.derive(master_secret)
        root_key = root_and_chain[:32]
        chain_key = root_and_chain[32:]

        self._print(f"Generated master secret: {master_secret}")
        self._print(f"Generated Root Key: {root_key}")
        self._print(f"Generated Chain Key: {chain_key}")

        self._contacts[recipient] = ClientContact(
            name=recipient,
            root_key=root_key,
            chain_key=chain_key,
            message_keys=[],
            session_init_metadata=SessionInitMetadata(
                i_pub_key=self._i_pub_key,
                ephemeral_pub=ephemeral_key.public_key,
                otpk_pub=otpk
            ),
            confirmed=False
        )

    def _do_encrypt_and_ratchet(self, message: bytes, contact: ClientContact) -> EncryptedMessage:
        message_key = self._get_message_key(contact.chain_key)
        (iv, mac, ciphertext) = encrypted_message = self._encrypt_message(message_key, message)

        encrypted_message = EncryptedMessage(
            ord=len(contact.message_keys),
            iv=iv,
            mac=mac,
            ciphertext=ciphertext
        )
        contact.message_keys.append(message_key)
        contact.chain_key = self._ratchet(contact.chain_key)
        return encrypted_message

    def _encrypt_message(self, message_key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
        iv = os.urandom(16)
        aes_key = message_key[:32]
        hmac_key = message_key[32:]

        # Pad
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Encrypt
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Create mac for validation
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(iv + ciphertext)
        mac = h.finalize()

        return iv, mac, ciphertext
    
    def _decrypt_message(self, message_key: bytes, encrypted_message: EncryptedMessage) -> bytes:
        iv = encrypted_message.iv
        aes_key = message_key[:32]

        # Decrypt
        ciphertext = encrypted_message.ciphertext
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext

    def _get_message_key(self, chain_key: bytes) -> bytes:
        h = hmac.HMAC(chain_key, hashes.SHA256())
        h.update(b'\x01')
        message_key = h.finalize()
        return message_key
        
    def _ratchet(self, chain_key: bytes) -> bytes:
        h = hmac.HMAC(chain_key, hashes.SHA256())
        h.update(b'\x02')
        chain_key = h.finalize()
        return chain_key

    def _gen_identity(self) -> tuple[ SigningKey, VerifyKey]:
        signing_key = SigningKey.generate()
        return signing_key, signing_key.verify_key
    
    def _gen_signed_pre_key(self, signing_key: SigningKey):
        priv_key = PrivateKey.generate()
        signature = signing_key.sign(priv_key.public_key.encode())
        return priv_key, priv_key.public_key, signature
    
    def _gen_one_time_pre_keys(self, count: int=20) -> list[tuple[PrivateKey, PublicKey]]:
        otpks = []
        for _ in range(count):
            priv_key = PrivateKey.generate()
            otpks.append((priv_key, priv_key.public_key))
        return otpks

    def _print(self, message: str):
        print(f"[Client {self._name}] {message}")