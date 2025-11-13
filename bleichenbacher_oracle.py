#!/usr/bin/env python3
import json
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
# Generate small RSA key for lab
bits = 512
p = getPrime(bits//2); q = getPrime(bits//2)
n = p*q; e = 65537; d = inverse(e, (p-1)*(q-1))
message = b"Secret lab message"
m = bytes_to_long(message)
c = pow(m, e, n)
def pkcs1_v1_5_unpad_check(m_bytes, k):
    if len(m_bytes) != k: return False
    return m_bytes[0] == 0x00 and m_bytes[1] == 0x02 and 0x00 in m_bytes[2:]
def oracle(cipher_int):
    m_int = pow(cipher_int, d, n)
    k = (n.bit_length() + 7) // 8
    m_bytes = long_to_bytes(m_int, k)
    return pkcs1_v1_5_unpad_check(m_bytes, k)
if __name__ == "__main__":
    print("Bleichenbacher demo oracle (local).")
    print("Public key (n,e):", n, e)
    print("Ciphertext (hex):", hex(c))
    print("Oracle padding_valid?:", oracle(c))
