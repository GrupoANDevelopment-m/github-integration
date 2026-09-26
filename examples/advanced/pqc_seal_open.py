"""
Advanced Example: PQC-based encryption/decryption.

Demonstrates forward-secure envelope encryption:
1. Generate KEM keypair
2. Encapsulate → ciphertext + shared secret
3. Use shared secret as AES key
4. Decapsulate to recover shared secret
5. Decrypt
"""
import os
import sys
sys.path.insert(0, '/workspace/goodware-v3')

from goodware.crypto.real_pqc import RealPQC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

pqc = RealPQC()

# 1. Generate KEM keypair (sender)
pk, sk, alg = pqc.kem_keypair("Kyber512")
print(f"1. Generated KEM keypair ({alg})")

# 2. Encapsulate (sender → recipient)
ct, ss1 = pqc.kem_encaps(pk, "Kyber512")
print(f"2. Encapsulated: ct={len(ct)}B, shared_secret={len(ss1)}B")

# 3. Encrypt plaintext with AES-256-GCM using shared_secret as key
plaintext = b"Secret message from sender to recipient"
iv = os.urandom(12)
cipher = Cipher(algorithms.AES(ss1), modes.GCM(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
tag = encryptor.tag
print(f"3. Encrypted with AES-GCM: {len(ciphertext)}B ciphertext + 16B tag")

# 4. Decapsulate (recipient)
ss2 = pqc.kem_decaps(sk, ct, "Kyber512")
print(f"4. Decapsulated: shared_secret={len(ss2)}B")
assert ss1 == ss2, "Shared secrets don't match!"

# 5. Decrypt
cipher2 = Cipher(algorithms.AES(ss2), modes.GCM(iv, tag), backend=default_backend())
decryptor = cipher2.decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()
print(f"5. Decrypted: {decrypted.decode()}")
assert decrypted == plaintext
print("✓ Forward-secure encryption works end-to-end")
