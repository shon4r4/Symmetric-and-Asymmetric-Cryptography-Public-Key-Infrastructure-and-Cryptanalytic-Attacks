#!/usr/bin/env python3
"""AES modes demo (ECB/CBC/GCM) using pycryptodome."""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import argparse, json
def encrypt_ecb(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return ct
def encrypt_cbc(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return ct
def encrypt_gcm(key, nonce, plaintext, associated_data=b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct, tag
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["ecb","cbc","gcm"], required=True)
    parser.add_argument("--keybits", type=int, default=256)
    parser.add_argument("--plaintext", type=str, default="Example plaintext for AES demo.")
    parser.add_argument("--nonce_reuse", action="store_true")
    parser.add_argument("--repeat", type=int, default=2)
    args = parser.parse_args()
    key = get_random_bytes(args.keybits // 8)
    pt = args.plaintext.encode()
    out = {"mode": args.mode, "key_hex": key.hex()}
    if args.mode == "ecb":
        ct = encrypt_ecb(key, pt)
        out.update({"cipher_hex": ct.hex()})
        print("ECB ciphertext (hex):", ct.hex())
    elif args.mode == "cbc":
        if args.nonce_reuse:
            iv = get_random_bytes(16)
            cts = []
            for i in range(args.repeat):
                ct = encrypt_cbc(key, iv, pt + b" %d" % i)
                cts.append(ct.hex())
            out.update({"iv_hex": iv.hex(), "cipher_hex_list": cts})
            print("CBC IV (hex):", iv.hex())
            for c in cts: print(c)
        else:
            iv = get_random_bytes(16)
            ct = encrypt_cbc(key, iv, pt)
            out.update({"iv_hex": iv.hex(), "cipher_hex": ct.hex()})
            print("CBC IV (hex):", iv.hex())
            print("CBC ciphertext (hex):", ct.hex())
    elif args.mode == "gcm":
        if args.nonce_reuse:
            nonce = get_random_bytes(12)
            results = []
            for i in range(args.repeat):
                pt_i = pt + b" %d" % i
                ct, tag = encrypt_gcm(key, nonce, pt_i)
                results.append({"cipher_hex": ct.hex(), "tag_hex": tag.hex()})
            out.update({"nonce_hex": nonce.hex(), "results": results})
            print("GCM nonce (hex):", nonce.hex())
            for r in results:
                print("cipher:", r["cipher_hex"])
                print("tag   :", r["tag_hex"])
        else:
            nonce = get_random_bytes(12)
            ct, tag = encrypt_gcm(key, nonce, pt)
            out.update({"nonce_hex": nonce.hex(), "cipher_hex": ct.hex(), "tag_hex": tag.hex()})
            print("GCM nonce (hex):", nonce.hex())
            print("GCM ciphertext (hex):", ct.hex())
            print("GCM tag (hex):", tag.hex())
    fname = "aes_demo_summary.json"
    with open(fname, "w") as f:
        json.dump(out, f, indent=2)
    print("\nSummary written to", fname)
if __name__ == "__main__": main()
