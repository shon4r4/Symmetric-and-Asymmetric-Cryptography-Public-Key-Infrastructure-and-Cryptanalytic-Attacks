#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long
import bleichenbacher_oracle as oracle_mod
def find_s_bruteforce(c, n, e, limit=1<<16):
    for s in range(1, limit):
        test = (c * pow(s, e, n)) % n
        if oracle_mod.oracle(test):
            return s
    return None
def main():
    n = oracle_mod.n; e = oracle_mod.e
    c = pow(bytes_to_long(oracle_mod.message), e, n)
    print("Starting naive Bleichenbacher-style search (demo)...")
    s = find_s_bruteforce(c, n, e)
    if s is None:
        print("No s found in search range.")
    else:
        print("Found s:", s)
if __name__ == "__main__": main()
