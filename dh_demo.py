#!/usr/bin/env python3
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
import hashlib
p = 0xFFFFFFFEFFFFFC2F
g = 5
def random_scalar():
    return bytes_to_long(get_random_bytes(16)) % (p-2) + 2
def derive_key(shared):
    h = hashlib.sha256(long_to_bytes(shared)).digest()
    return h
def main():
    print("Diffie-Hellman demo (finite field)")
    a = random_scalar(); b = random_scalar()
    A = pow(g, a, p); B = pow(g, b, p)
    s1 = pow(B, a, p); s2 = pow(A, b, p)
    assert s1 == s2
    key = derive_key(s1)
    print("Alice private a:", a)
    print("Bob private b  :", b)
    print("Alice public A :", hex(A))
    print("Bob public B   :", hex(B))
    print("Shared secret  :", hex(s1))
    print("Derived key (SHA-256):", key.hex())
if __name__ == '__main__': main()
