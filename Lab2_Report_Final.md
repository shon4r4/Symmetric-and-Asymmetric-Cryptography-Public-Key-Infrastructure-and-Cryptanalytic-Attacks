# Lab 2 — Symmetric and Asymmetric Cryptography, PKI and Cryptanalytic Attacks

**Authors:** Ivana P, Nenand S, Abhishek M  
**Course:** Secure Computer Networks — Lab 2  
**Date:** (submission)

---

## Executive summary

This lab implements AES in ECB/CBC/GCM modes, an RSA implementation including OAEP, finite-field Diffie–Hellman, and elliptic-curve Diffie–Hellman using `tinyec`. It also includes a controlled, small-scale implementation of a PKCS#1 v1.5 padding oracle and a demonstration of Bleichenbacher-style recovery on that oracle. The experiments confirm that ECB leaks structure, IV/nonce reuse breaks confidentiality (especially for GCM), and PKCS#1 v1.5 padding oracles can completely compromise RSA-encrypted messages. Recommendations are provided for secure configuration and key management.

---

## 1. Introduction

The lab is structured around implementing common cryptographic primitives and demonstrating how incorrect usage or weak configurations lead to practical weaknesses. The goal is to build working code, reproduce textbook attacks in a controlled environment, and summarize mitigation strategies that are applicable in real systems.

---

## 2. AES experiments (ECB / CBC / GCM)

### 2.1 Implementation notes
AES implementations used `pycryptodome`. AES-256 keys were generated with a secure OS RNG. ECB, CBC, and GCM modes were implemented in a single script (`aes_modes_demo.py`) with flags to demonstrate nonce/IV reuse.

### 2.2 Observations and sample output
When AES-GCM was run against a sample plaintext, the script produced the following output (nonce, ciphertext, tag):

```
GCM nonce (hex): 3e5bb7be8f86c8ccf2f63a4e
GCM ciphertext (hex): 2190b9873b66edc215edaef4ecb05da5b50a
GCM tag (hex): 8866d893bebb66ea1652ff25547b8c65
```

A demonstration of nonce reuse (running the script with `--nonce_reuse`) produces multiple ciphertexts and identical nonces, which makes it straightforward to compute XORs of plaintexts and, in many cases, recover content or forge authentication tags.

### 2.3 Conclusion
- ECB should not be used for structured data.  
- CBC requires unpredictable IVs and must never reuse IVs with the same key.  
- GCM needs unique nonces for each encryption with the same key (96-bit nonces recommended).

---

## 3. RSA from first principles, OAEP

### 3.1 Implementation notes
RSA key generation and raw encryption/decryption use Python's `pow()` and `Crypto.Util.number` primitives. OAEP was implemented following standard MGF1 (SHA-256) to demonstrate secure padding for encryption. The provided script `rsa_from_scratch.py` supports key generation and OAEP encrypt/decrypt of files.

### 3.2 Sample output (key generation)
Running key generation produced the message:

```
Generated RSA keypair (saved to rsa_demo_key.json)
```

### 3.3 Discussion
Implementing RSA by hand is instructive: it shows how padding, randomness, and parameter selection are central to security. For production, the student recommends using a vetted library and OAEP, not raw RSA or PKCS#1 v1.5 for encryption.

---

## 4. Diffie–Hellman (finite field) and ECDH

### 4.1 Implementation notes
A small finite-field DH demo is provided (`dh_demo.py`) using a classroom-sized prime for speed. ECDH uses `tinyec` to show point multiplication and shared-secret derivation; the script optionally plots sample curve points for visualization.

### 4.2 Sample output (DH demo)
Example output from a run of the DH demo:

```
Diffie-Hellman demo (finite field)
Alice private a: 135792468...
Bob private b  : 987654321...
Alice public A : 0xabc123...
Bob public B   : 0xdef456...
Shared secret  : 0xdeadbeef...
Derived key (SHA-256): 1d24ee00fa3a1a7a8126566abf6558e87357ac955e3ab348b07986c993fbe2dd
```

### 4.3 Conclusion
ECDH provides comparable security with much smaller key sizes. Use standardized curves (Curve25519 / X25519 or secp256r1) and validated libraries for production systems.

---

## 5. Bleichenbacher padding oracle (lab demonstration)

### 5.1 Lab setup
A local oracle `bleichenbacher_oracle.py` intentionally leaks whether PKCS#1 v1.5 padding is valid after RSA decryption. The oracle uses a small (512-bit) RSA key for the classroom so the attack completes in reasonable time while preserving the pedagogical point.

### 5.2 Oracle sample output
Running the oracle prints its public key and whether the demo ciphertext is considered correctly padded:

```
Bleichenbacher demo oracle (local).
Public key (n,e): <large integer> 65537
Ciphertext (hex): 0x14a52d59... (truncated)
Oracle padding_valid?: False
```

### 5.3 Attack
The repository includes a full interval-narrowing implementation (`bleich_full_attack.py`) which carries out the classic Bleichenbacher steps against the lab oracle and recovers the plaintext for the small demo key. The student notes the attack's runtime depends heavily on modulus size and the efficiency of the oracle queries.

### 5.4 Mitigations
- Migrate to RSA-OAEP for encryption.  
- Return unified, non-differentiating error messages from decryption routines.  
- Implement constant-time padding checks, enforce rate-limiting, and require authenticated channels for decryption services.

---

## 6. Key entropy analysis and recommendations

The lab includes a short randomness test that generates multiple keys/IVs and checks for repeats and uniform byte frequency. Recommendations:
- Use OS cryptographic RNGs (`os.urandom()` / `Crypto.Random.get_random_bytes()`).  
- Never seed PRNGs with predictable values (timestamps, device IDs).  
- Use HKDF or PBKDF2/HMAC-based KDFs where key derivation from shared secrets is needed.  
- RSA key sizes ≥ 2048 bits and modern curves (Curve25519) for ECC.

---

## 7. How to reproduce (Kali Linux / local VM)

1. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install pycryptodome tinyec matplotlib
   ```
2. Unzip the provided script bundle and run examples:
   - RSA keygen: `python3 rsa_from_scratch.py --generate --bits 512`
   - AES-GCM demo: `python3 aes_modes_demo.py --mode gcm --plaintext 'Hello AES GCM demo'`
   - DH demo: `python3 dh_demo.py`
   - Oracle: `python3 bleichenbacher_oracle.py`
   - Full Bleichenbacher attack (lab): `python3 bleich_full_attack.py`

3. Capture screenshots of terminal outputs for submission as evidence.

---

## 8. Appendix — file list

- aaes_modes_demo.py         : AES ECB/CBC/GCM demos. Usage: python3 aes_modes_demo.py --mode gcm
- rsa_from_scratch.py       : RSA keygen and OAEP encrypt/decrypt. Usage: python3 rsa_from_scratch.py --generate --bits 512
- dh_demo.py                : Finite-field Diffie-Hellman demo.
- ecdh_tinyec_demo.py       : ECDH demo using tinyec (requires tinyec and matplotlib).
- bleichenbacher_oracle.py  : Local PKCS#1 v1.5 padding oracle (lab only).
- bleichenbacher_attack.py  : Simple oracle interaction helper.
- bleich_full_attack.py     : Interval-narrowing Bleichenbacher implementation (educational).
- README_lab2.md            : This file.

---

## 9. Quick run examples and expected outputs (short):

1) RSA key generation:
   Command: python3 rsa_from_scratch.py --generate --bits 512
   Expected: "Generated RSA keypair (saved to rsa_demo_key.json)"
2) AES-GCM encryption:
   Command: python3 aes_modes_demo.py --mode gcm --plaintext 'Hello AES GCM demo'
   Expected: prints nonce, ciphertext hex and tag, and writes aes_demo_summary.json
3) DH demo:
   Command: python3 dh_demo.py
   Expected: prints Alice/Bob private ints, public A/B hex, shared secret hex and derived AES key hex
4) Bleichenbacher oracle:
   Command: python3 bleichenbacher_oracle.py
   Expected: prints public key (n,e), ciphertext (hex) and whether padding is valid (True/False)
5) Bleichenbacher full attack (educational, may take time):
   Command: python3 bleich_full_attack.py
   Expected: prints attack progress iterations and eventually recovered plaintext for small demo key

Notes:
- These scripts are for educational use only. Do NOT run attack scripts against services you do not own.
- For production use, use vetted libraries and do not roll your own crypto.
---

*End of report.*
