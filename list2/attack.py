import random
from sympy import randprime


def egcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception(f"There's no inverse of {a} mod {m}")
    else:
        return x % m


def GenModulus(w):
    """Generate primes and modulus used in RSA."""
    n = len(w) // 2
    p = randprime(2 ** n, 2 ** (n + 1))
    while (q := randprime(2 ** n, 2 ** (n + 1))) == p:
        pass
    N = p * q
    return N, p, q


def GenRSA(w):
    """Generate values necessary for RSA encryption."""
    N, p, q = GenModulus(w)
    m = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, m)
    return N, e, d, p, q


def enc(x, N, e):
    """Encrypt x using RSA scheme."""
    return pow(x, e, N)


def dec(c, N, d):
    """Decrypt x using RSA scheme."""
    return pow(c, d, N)


def fast_pow(c, N, d):
    """Fast exponentiation algorithm."""
    d_bin = "{0:b}".format(d)
    d_len = len(d_bin)
    reductions = 0
    h = 0
    x = c
    for j in range(1, d_len):
        x, r = mod_reduce(x ** 2, N)
        reductions = reductions + r
        if d_bin[j] == "1":
            x, r = mod_reduce(x * c, N)
            reductions = reductions + r
            h = h + 1
    return x, h, reductions


def mod_reduce(a, b):
    """Reduce a if a >=b and return whether a reduction was performed."""
    reductions = 0
    if a >= b:
        a = a % b
        reductions = 1
    return a, reductions


def attack(N, e, d, keylen):
    """Timing attack algorithm as described in chapter 3.4 of
    http://www.cs.jhu.edu/~fabian/courses/CS600.624/Timing-full.pdf.
    N, e, d were used to generate a test set."""
    # First bit of the key
    key = "1"
    # n samples
    samples = random.sample(range(2, N), 10000000)
    # Query and get number of reductions for the test set
    reduced_samples = [fast_pow(m, N, d)[2] for m in samples]
    # Generate key
    for _ in range(keylen - 2):
        # 1 then 0, 1 then 1, 0 then 0, 0 then 1
        set10, set11, set00, set01 = [], [], [], []
        for i, m in enumerate(samples):
            mtemp = fast_pow(m, N, int(f"{key}0", 2))[0]
            # i-th bit is set
            x, _ = mod_reduce(mtemp * m, N)
            if mod_reduce(x ** 2, N)[1] == 0:
                set10.append(i)
            else:
                set11.append(i)
            # i-th bit is not set
            if mod_reduce(mtemp ** 2, N)[1] == 0:
                set00.append(i)
            else:
                set01.append(i)
        # Calculate average reductions for the sets
        result10 = sum(reduced_samples[i] for i in set10) / len(set10)
        result11 = sum(reduced_samples[i] for i in set11) / len(set11)
        result00 = sum(reduced_samples[i] for i in set00) / len(set00)
        result01 = sum(reduced_samples[i] for i in set01) / len(set01)
        # If d1 > d0 then bit is probably 1 else 0
        d0 = result01 - result00
        d1 = result11 - result10
        # Result bit
        n = int(d1 > d0)
        key += str(n)
    return [key+"1", key+"0"]


N, e, d, p, q = GenRSA("1111111111111111111111111")
print(f"RSA: N = {N}; e = {e}; d = {d}; p = {p}; q = {q}")

print("key: {0:b}".format(d))
keylen = len("{0:b}".format(d))

keys = attack(N, e, d, keylen)
print("Possible keys:")
print(keys)

if "{0:b}".format(d) in keys:
    print("Key found!")
else:
    print("Key not found!")
