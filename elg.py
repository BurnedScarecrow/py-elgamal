import random
from Crypto.Util.number import *
from Crypto.Random import get_random_bytes
# from Crypto.PublicKey import ElGamal


def modInverse(number, mod):
    x1 = 1
    x2 = 0
    x3 = mod
    y1 = 0
    y2 = 1
    y3 = number

    q = int(x3 / y3)

    t1 = x1 - q * y1
    t2 = x2 - q * y2
    t3 = x3 - q * y3

    while y3 != 1:
        x1 = y1
        x2 = y2
        x3 = y3
        y1 = t1
        y2 = t2
        y3 = t3

        q = int(x3 / y3)
        t1 = x1 - q * y1
        t2 = x2 - q * y2
        t3 = x3 - q * y3

    if y2 < 0:
        while y2 < 0:
            y2 = y2 + mod

    return y2


def gcd(a, b):
    if a % b == 0:
        return b
    else:
        return gcd(b, a % b)


class Elgamal:
    def __init__(self):
        print("-----------------------")
        print("key generation")
        print("-----------------------")

        self.g = 2
        self.p = getPrime(32, randfunc=get_random_bytes)
        self.x = random.randint(1, self.p-2)
        self.y = pow(self.g, self.x, self.p)

        """config = ElGamal.generate(512, get_random_bytes)
        p = getattr(config, 'p')"""

        print("public key: (p=", self.p, ", g=", self.g, ", y=", self.y, ")")
        print("private key: ", self.x)

    def get_public(self):
        return (self.p, self.g, self.y)

    def get_private(self):
        return self.x

        # ------------------------------
        # digital signatures

    def sign(self, hash):
        print("-----------------------")
        print("digital signature")
        print("-----------------------")

        print("signing")

        k = random.randint(1, self.p-1)

        while gcd(self.p-1, k) != 1:
            k = random.randint(1, self.p-1)

        #print("random key: ",k)

        r = pow(self.g, k, self.p)
        s = (hash - self.x*r) * modInverse(k, self.p-1) % (self.p-1)

        return (r, s)

    def verify(self, hash, p, g, y, r, s):
        print("verification")
        left = pow(g, hash, p)
        right = (pow(y, r, p) * pow(r, s, p)) % p

        print("checkpoint1: ", left)
        print("checkpoint2: ", right)

        if left == right:
            print("signature is valid")
            return True
        else:
            print("invalid signature detected")
            return False


# print("-----------------------")
# print("encryption decryption")
# print("-----------------------")
# print("encryption")
# # Bob knows g, p, y

# m = 100
# k = random.randint(1, p-1)

# c1 = pow(g, k, p)
# c2 = m * pow(y, k, p) % p

# print("ciphertext: (c1=", c1, ", c2=", c2, ")")

# # bob sends c1, c2 pair to alice

# print("decryption")

# restored = c2 * pow(c1, (p-1-x), p) % p
# print("restored message: ", restored)


elg = Elgamal()
(p, g, y) = elg.get_public()

hash = 12345

(r, s) = elg.sign(hash)
print("signature: (r =", r, ", s =", s, ")")


elg.verify(hash, p, g, y, r, s)
