#!/usr/bin/env python3
"""RSA from scratch with OAEP encode/decode (SHA-256).
Educational only."""
import argparse, json, hashlib
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes

KEYFILE = "rsa_demo_key.json"

def generate_keys(bits=512):
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    n = p * q
    phi = (p-1)*(q-1)
    e = 65537
    while GCD(e, phi) != 1:
        e += 2
    d = inverse(e, phi)
    key = {"n": n, "e": e, "d": d, "bits": bits}
    with open(KEYFILE, "w") as f:
        json.dump({k: str(v) for k,v in key.items()}, f)
    print("Generated RSA keypair (saved to {})".format(KEYFILE))
    return key

def load_keys():
    with open(KEYFILE, "r") as f:
        j = json.load(f)
    return {k: int(v) for k,v in j.items()}

def i2osp(x, x_len):
    return x.to_bytes(x_len, 'big')

def os2ip(b):
    return int.from_bytes(b, 'big')

def mgf1(seed, mask_len, hash_func=hashlib.sha256):
    hlen = hash_func().digest_size
    if mask_len > (1 << 32) * hlen:
        raise ValueError("mask too long")
    T = b''
    for counter in range(0, -(-mask_len // hlen)):
        C = counter.to_bytes(4, 'big')
        T += hash_func(seed + C).digest()
    return T[:mask_len]

def oaep_encode(message, k, label=b'', hash_func=hashlib.sha256):
    hlen = hash_func().digest_size
    mlen = len(message)
    if mlen > k - 2*hlen - 2:
        raise ValueError("message too long")
    lhash = hash_func(label).digest()
    ps = b'\x00' * (k - mlen - 2*hlen - 2)
    db = lhash + ps + b'\x01' + message
    seed = get_random_bytes(hlen)
    db_mask = mgf1(seed, k - hlen - 1, hash_func)
    masked_db = bytes(x ^ y for x,y in zip(db, db_mask))
    seed_mask = mgf1(masked_db, hlen, hash_func)
    masked_seed = bytes(x ^ y for x,y in zip(seed, seed_mask))
    em = b'\x00' + masked_seed + masked_db
    return em

def oaep_decode(em, k, label=b'', hash_func=hashlib.sha256):
    hlen = hash_func().digest_size
    if len(em) != k or k < 2*hlen + 2:
        raise ValueError("decryption error")
    if em[0] != 0x00:
        raise ValueError("decryption error")
    masked_seed = em[1:1+hlen]
    masked_db = em[1+hlen:]
    seed_mask = mgf1(masked_db, hlen, hash_func)
    seed = bytes(x ^ y for x,y in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, k - hlen -1, hash_func)
    db = bytes(x ^ y for x,y in zip(masked_db, db_mask))
    lhash = hash_func(label).digest()
    if db[:hlen] != lhash:
        raise ValueError("decryption error")
    sep_idx = db.find(b'\x01', hlen)
    if sep_idx < 0:
        raise ValueError("decryption error")
    message = db[sep_idx+1:]
    return message

def raw_rsa_encrypt(m_int, e, n): return pow(m_int, e, n)
def raw_rsa_decrypt(c_int, d, n): return pow(c_int, d, n)

def oaep_encrypt_file(infile, outfile):
    key = load_keys()
    n = key['n']; e = key['e']
    k = (n.bit_length() + 7) // 8
    with open(infile, 'rb') as f: m = f.read()
    em = oaep_encode(m, k)
    m_int = os2ip(em)
    c = raw_rsa_encrypt(m_int, e, n)
    with open(outfile, 'wb') as f: f.write(i2osp(c, k))
    print('OAEP encrypted ->', outfile)

def oaep_decrypt_file(infile, outfile):
    key = load_keys()
    n = key['n']; d = key['d']
    k = (n.bit_length() + 7) // 8
    with open(infile, 'rb') as f: c = f.read()
    c_int = os2ip(c)
    m_int = raw_rsa_decrypt(c_int, d, n)
    em = i2osp(m_int, k)
    m = oaep_decode(em, k)
    with open(outfile, 'wb') as f: f.write(m)
    print('OAEP decrypted ->', outfile)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--generate', action='store_true')
    parser.add_argument('--bits', type=int, default=512)
    parser.add_argument('--oaep-encrypt', action='store_true')
    parser.add_argument('--oaep-decrypt', action='store_true')
    parser.add_argument('--in', dest='infile', help='input filename')
    parser.add_argument('--out', dest='outfile', help='output filename')
    args = parser.parse_args()
    if args.generate:
        generate_keys(bits=args.bits)
    elif args.oaep_encrypt:
        if not args.infile or not args.outfile:
            print('Provide --in and --out for oaep encrypt'); return
        oaep_encrypt_file(args.infile, args.outfile)
    elif args.oaep_decrypt:
        if not args.infile or not args.outfile:
            print('Provide --in and --out for oaep decrypt'); return
        oaep_decrypt_file(args.infile, args.outfile)
    else:
        parser.print_help()

if __name__ == '__main__': main()
