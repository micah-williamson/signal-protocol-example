from __future__ import annotations
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

from envelope import ClientEnvelope, EncryptedMessage, MessageChain, SessionInitMetadata
from server import Server

@dataclass
class ClientContact:
    name: str
    companions: list[str]

    # Shared root key secret
    root_key: bytes

    # Sending chain and ephemeral keys may be optional if we are not the last sender
    sending_chain_key: Optional[bytes]
    sending_ephemeral_priv: Optional[PrivateKey]
    sending_ord: int

    # Receiving chain keyed off of ephemeral public key. Receiving chains will be kept this way
    # in case we receive out of order messages we can still decrypt those messages. The last 
    # ephemeral pub is also tracked so root key ratcheting can be performed
    receiving_chains: dict[PublicKey, MessageChain]
    last_ephemeral_pub: Optional[PublicKey]

    # Initiator fields. These values only exist if WE initiated the chat.
    session_init_metadata: Optional[SessionInitMetadata] = None

@dataclass
class Client:

    name: str
    _companions: list[Client]

    # Identity
    _i_priv_key: SigningKey
    _i_pub_key: VerifyKey

    _signed_pre_key: tuple[PrivateKey, PublicKey, SignedMessage]

    # Genererated one-time pre keys shared with the server. Used for reverse pub->priv otpk lookup
    _one_time_pre_keys: list[tuple[PrivateKey, PublicKey]]

    # Server connection
    _server: Server

    _contacts: dict[str, ClientContact]

    def __init__(self, name: str):
        self.name = name
        (
            self._i_priv_key, 
            self._i_pub_key
        ) = self._gen_identity()
        self._signed_pre_key = self._gen_signed_pre_key(self._i_priv_key)
        self._one_time_pre_keys = self._gen_one_time_pre_keys()
        self._companions = []
        self._contacts = {}

    def connect(self, server: Server):
        self._server = server
        server.register(self.receive, self.name, self._i_pub_key, self._signed_pre_key[1], 
                        self._signed_pre_key[2], [otpk[1] for otpk in self._one_time_pre_keys])
            
        
    def add_companion(self, companion: Client):
        companion.connect(self._server)
        self._companions.append(companion)
        self._server.set_companions(self.name, [c.name for c in self._companions])
        
    def send(self, recipient: str, message: bytes):
        if recipient not in self._contacts:
            self._init_session_as_initiator(recipient)

        self._print(f"Sending message [to {recipient}]: {message}")
        contact = self._contacts[recipient]

        self._send_single(contact, message)

        for companion in contact.companions:
            self._print(f"Sending to {recipient} companion: {companion}")
            self.send(companion, message)

    def _send_single(self, contact: ClientContact, message: bytes):
        session_init_metadata = None
        if not contact.receiving_chains:
            # If there are no receiving chains then we need to continue sending the init metadata
            # so the receiving can create their first sending (our receiving) chain
            session_init_metadata = contact.session_init_metadata
        
        if contact.sending_chain_key == None:
            self._print("Taking over as sender and ratcheting root key")
            last_ephemeral_pub = contact.last_ephemeral_pub
            if last_ephemeral_pub is None:
                raise Exception("Unable to ratchet root key. No last_ephemeral_pub")

            new_ephemeral_priv = PrivateKey.generate()
            new_shared_secret = crypto_scalarmult(new_ephemeral_priv.encode(), 
                                                  last_ephemeral_pub.encode())
            new_root_key, new_chain_key = self._gen_root_and_chain_key(new_shared_secret, 
                                                                       salt=contact.root_key)
            contact.root_key = new_root_key
            contact.sending_chain_key = new_chain_key
            contact.sending_ephemeral_priv = new_ephemeral_priv
            contact.sending_ord = 0

        encrypted_message = self._do_encrypt_and_ratchet(message, contact)
        envelope = ClientEnvelope(
            to=contact.name,
            from_=self.name,
            sender_companions=[c.name for c in self._companions],
            encrypted_message=encrypted_message,
            session_init_metadata=session_init_metadata
        )
        self._server.send(envelope)

    def receive(self, envelope: ClientEnvelope):
        self._print(f"Received message from {envelope.from_}")

        if envelope.from_ not in self._contacts:
            self._print(f"New contact. Initializing session")
            self._init_session_as_recipient(envelope.from_, envelope)
        
        contact = self._contacts[envelope.from_]
        encrypted_message = envelope.encrypted_message

        ephemeral_pub = encrypted_message.ephemeral_pub
        if ephemeral_pub not in contact.receiving_chains:
            self._print("Got new ephemeral key from sender. Ratcheting root key")
            sending_ephemeral_priv = contact.sending_ephemeral_priv
            if sending_ephemeral_priv is None:
                raise Exception("Unable to ratchet root key. No sending_ephemeral_priv")
            
            new_shared_secret = crypto_scalarmult(sending_ephemeral_priv.encode(), 
                                                  ephemeral_pub.encode())
            new_root_key, new_chain_key = self._gen_root_and_chain_key(new_shared_secret, 
                                                                       salt=contact.root_key)
            contact.root_key = new_root_key
            contact.receiving_chains[ephemeral_pub] = MessageChain(
                chain_key=new_chain_key,
                ephemeral_pub=ephemeral_pub,
                message_keys=[],
                ratchet_count=0
            )
            # Reset sending fields because we are no longer the sender
            contact.sending_chain_key = None
            contact.sending_ephemeral_priv = None
            contact.sending_ord = 0

        receiving_chain = contact.receiving_chains[ephemeral_pub]
        contact.last_ephemeral_pub = ephemeral_pub

        # Ratchet chain key until we have the message keys we need
        rc = receiving_chain.ratchet_count
        while rc < encrypted_message.ord:
            rc += 1
            receiving_chain.message_keys.append(
                (rc, self._get_message_key(receiving_chain.chain_key))
            )
            receiving_chain.chain_key = self._ratchet(receiving_chain.chain_key)
        receiving_chain.ratchet_count = rc
        
        # Find matching message key and remove it
        message_key_pair = [mk for mk in receiving_chain.message_keys
                            if mk[0] == encrypted_message.ord][0]
        message_key = message_key_pair[1]
        receiving_chain.message_keys.remove(message_key_pair)
        
        # Decrypt with message 
        decrypted_message_text = self._decrypt_message(message_key, encrypted_message)
        
        self._print(f"Got decrypted message: {decrypted_message_text}")                   

    def _init_session_as_recipient(self, initiator: str, envelope: ClientEnvelope):
        sim = envelope.session_init_metadata
        if sim is None:
            raise Exception("Session init metadata not found")
        
        self._print(f"Initializing chat session with {initiator} as recipient")
        i_priv_key = self._i_priv_key.to_curve25519_private_key()
        s_i_pub_key = sim.i_pub_key.to_curve25519_public_key()
        pre_key_priv = self._signed_pre_key[0]
        ephemeral_pub = envelope.encrypted_message.ephemeral_pub

        otpk_priv = [otpk[0] for otpk in self._one_time_pre_keys if otpk[1] == sim.otpk_pub][0]
        dh1 = crypto_scalarmult(pre_key_priv.encode(), s_i_pub_key.encode())
        dh2 = crypto_scalarmult(i_priv_key.encode(), ephemeral_pub.encode())
        dh3 = crypto_scalarmult(pre_key_priv.encode(), ephemeral_pub.encode())
        dh4 = crypto_scalarmult(otpk_priv.encode(), ephemeral_pub.encode())
        master_secret = dh1 + dh2 + dh3 + dh4

        # Generate session keys
        root_key, chain_key = self._gen_root_and_chain_key(master_secret)

        self._print(f"Generated master secret: {master_secret}")
        self._print(f"Generated Root Key: {root_key}")
        self._print(f"Generated Chain Key: {chain_key}")

        self._contacts[initiator] = ClientContact(
            name=initiator,
            companions=envelope.sender_companions,
            root_key=root_key,
            sending_chain_key=None,
            sending_ephemeral_priv=None,
            sending_ord=0,
            receiving_chains={
                ephemeral_pub: MessageChain(
                    chain_key=chain_key,
                    ephemeral_pub=ephemeral_pub,
                    message_keys=[],
                    ratchet_count=0
                )
            },
            last_ephemeral_pub=ephemeral_pub
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
        root_key, chain_key = self._gen_root_and_chain_key(master_secret)

        self._print(f"Generated master secret: {master_secret}")
        self._print(f"Generated Root Key: {root_key}")
        self._print(f"Generated Chain Key: {chain_key}")

        self._contacts[recipient] = ClientContact(
            name=recipient,
            companions=[],
            root_key=root_key,
            sending_chain_key=chain_key,
            sending_ephemeral_priv=ephemeral_key,
            sending_ord=0,
            receiving_chains={},
            last_ephemeral_pub=None,
            session_init_metadata=SessionInitMetadata(
                i_pub_key=self._i_pub_key,
                otpk_pub=otpk
            )
        )

    def _do_encrypt_and_ratchet(self, message: bytes, contact: ClientContact) -> EncryptedMessage:
        chain_key = contact.sending_chain_key
        ephemeral_priv = contact.sending_ephemeral_priv
        if chain_key is None or ephemeral_priv is None:
            raise Exception("Unable to encrypt message before sending chain/eph is initialized")
        
        message_key = self._get_message_key(chain_key)
        (iv, mac, ciphertext) = encrypted_message = self._encrypt_message(message_key, message)

        contact.sending_ord += 1
        encrypted_message = EncryptedMessage(
            ord=contact.sending_ord,
            iv=iv,
            mac=mac,
            ciphertext=ciphertext,
            ephemeral_pub=ephemeral_priv.public_key
        )
        contact.sending_chain_key = self._ratchet(chain_key)

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
        hmac_key = message_key[32:]

        # Verify
        verifier = hmac.HMAC(hmac_key, hashes.SHA256())
        verifier.update(iv + encrypted_message.ciphertext)
        try:
            verifier.verify(encrypted_message.mac)
        except Exception:
            raise Exception("HMAC verification failed on")

        # Decrypt
        ciphertext = encrypted_message.ciphertext
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext
    
    def _gen_root_and_chain_key(self, shared_secret: bytes, 
                                salt: Optional[bytes]=None) -> tuple[bytes, bytes]:
        deriver = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            info=b"WhisperText",
            salt=b'\x00' * 32 if salt is None else salt
        )
        root_and_chain = deriver.derive(shared_secret)
        root_key = root_and_chain[:32]
        chain_key = root_and_chain[32:]
        return root_key, chain_key

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
        print(f"[Client {self.name}] {message}")