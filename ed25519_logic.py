import nacl.signing
from cryptography.hazmat.primitives.asymmetric import ed25519

class Ed25519Service:
    @staticmethod
    def sign_pynacl(private_key_hex, message_bytes):
        # Бібліотека №1: PyNaCl
        seed = bytes.fromhex(private_key_hex)
        signing_key = nacl.signing.SigningKey(seed)
        return signing_key.sign(message_bytes).signature

    @staticmethod
    def sign_cryptography(private_key_hex, message_bytes):
        # Бібліотека №2: Cryptography
        seed = bytes.fromhex(private_key_hex)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        return private_key.sign(message_bytes)