#!/usr/bin/env python3
import argparse, hashlib
try:
    from tinyec import registry, ec
    import matplotlib.pyplot as plt
except Exception as e:
    print("Required modules not found. Please install tinyec and matplotlib.")
    raise SystemExit(1)
def derive_key(point):
    x = point.x
    b = x.to_bytes((x.bit_length()+7)//8, 'big')
    return hashlib.sha256(b).digest()
def plot_curve(curve, pA, pB):
    plt.scatter([pA.x],[pA.y], label='Alice pub')
    plt.scatter([pB.x],[pB.y], label='Bob pub')
    plt.legend(); plt.title("Curve points (sample)"); plt.show()
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--curve", default="secp256r1"); parser.add_argument("--plot", action="store_true")
    args = parser.parse_args()
    curve = registry.get_curve(args.curve)
    privA = ec.random_secret(); privB = ec.random_secret()
    pubA = privA * curve.g; pubB = privB * curve.g
    shared1 = privA * pubB; shared2 = privB * pubA
    assert shared1 == shared2
    key = derive_key(shared1)
    print("Curve:", args.curve)
    print("Alice priv (int):", privA)
    print("Bob priv   (int):", privB)
    print("Alice pub (x,y):", pubA.x, pubA.y)
    print("Bob pub   (x,y):", pubB.x, pubB.y)
    print("Shared x:", shared1.x)
    print("Derived key (SHA-256):", key.hex())
    if args.plot: plot_curve(curve, pubA, pubB)
