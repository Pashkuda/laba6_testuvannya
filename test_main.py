import pytest
import time
from ed25519_logic import Ed25519Service

SK_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
EXPECTED_SIG = "e5564300c360ac72908f0c198428303474c018c847d057a0c71bd218036e166c4362b9b1531e21975e112521191a2717010471933c0973550868f3621404c00d"
MSG = b"" 

def test_correctness():
    # Завдання 7: Коректність 
    sig_pynacl = Ed25519Service.sign_pynacl(SK_HEX, MSG)
    assert sig_pynacl.hex() == EXPECTED_SIG
    
    sig_crypto = Ed25519Service.sign_cryptography(SK_HEX, MSG)
    assert sig_crypto.hex() == EXPECTED_SIG

def test_performance():
    # Завдання 8: Продуктивність (1000 операцій) 
    iterations = 1000
    start = time.time()
    for _ in range(iterations):
        Ed25519Service.sign_pynacl(SK_HEX, b"speed_test")
    pynacl_dur = time.time() - start
    
    start = time.time()
    for _ in range(iterations):
        Ed25519Service.sign_cryptography(SK_HEX, b"speed_test")
    crypto_dur = time.time() - start
    
    print(f"\nPyNaCl: {pynacl_dur:.4f}s | Cryptography: {crypto_dur:.4f}s")