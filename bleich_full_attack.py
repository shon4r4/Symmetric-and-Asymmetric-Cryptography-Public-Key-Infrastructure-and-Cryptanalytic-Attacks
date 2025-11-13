#!/usr/bin/env python3
# Full Bleichenbacher interval-narrowing attack for demo (small keys)
import math, time
from Crypto.Util.number import long_to_bytes, bytes_to_long
import bleichenbacher_oracle as oracle_mod
n = oracle_mod.n; e = oracle_mod.e
# use ciphertext of known message for demo
c = pow(bytes_to_long(oracle_mod.message), e, n)
k = (n.bit_length() + 7) // 8
B = 2 ** (8*(k-2))
def ceil_div(a,b): return -(-a//b)
def find_s_start():
    s = ceil_div(n, 3*B)
    while True:
        test = (c * pow(s, e, n)) % n
        if oracle_mod.oracle(test): return s
        s += 1
def attack():
    s = find_s_start(); print("s1 =", s)
    M = [(2*B, 3*B - 1)]; i = 1
    while True:
        newM = []
        for a,b in M:
            rmin = ceil_div(a*s - 3*B + 1, n)
            rmax = (b*s - 2*B) // n
            for r in range(rmin, rmax+1):
                new_a = max(a, ceil_div(2*B + r*n, s))
                new_b = min(b, (3*B -1 + r*n) // s)
                if new_a <= new_b: newM.append((new_a, new_b))
        M = newM
        print("Iteration", i, "intervals:", len(M))
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = M[0][0]; return long_to_bytes(m)
        # find next s (naive increment)
        s += 1
        while not oracle_mod.oracle((c * pow(s, e, n)) % n):
            s += 1
        i += 1
def main():
    start = time.time()
    recovered = attack()
    if recovered: print("Recovered plaintext (raw):", recovered)
    print("Elapsed:", time.time() - start)
if __name__ == "__main__": main()
