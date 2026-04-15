import pytest
import time
from ed25519_logic import Ed25519Service

# Справжні еталонні дані з RFC 8032 Section 7.1
SK_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" # nosec
# Оновлений і на 100% правильний очікуваний підпис
EXPECTED_SIG_HEX = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" # nosec
MSG = b""

def test_correctness():
    # Завдання 7: Перевірка коректності
    expected_bytes = bytes.fromhex(EXPECTED_SIG_HEX)
    
    sig_pynacl = Ed25519Service.sign_pynacl(SK_HEX, MSG)
    assert sig_pynacl == expected_bytes
    
    sig_crypto = Ed25519Service.sign_cryptography(SK_HEX, MSG)
    assert sig_crypto == expected_bytes

def test_performance():
    # Завдання 8: Порівняння продуктивності
    iterations = 1000
    start = time.time()
    for _ in range(iterations):
        Ed25519Service.sign_pynacl(SK_HEX, b"test")
    pynacl_dur = time.time() - start
    
    start = time.time()
    for _ in range(iterations):
        Ed25519Service.sign_cryptography(SK_HEX, b"test")
    crypto_dur = time.time() - start
    print(f"\nPyNaCl: {pynacl_dur:.4f}s | Cryptography: {crypto_dur:.4f}s")