from Crypto.Util.number import *
from Crypto import Random
import Crypto
import libnum
import sys
from random import randint
import hashlib

bits = 32
msg = "Hello"

if (len(sys.argv) > 1):
    msg = str(sys.argv[1])
if (len(sys.argv) > 2):
    bits = int(sys.argv[2])


class Elgamal:

    def __init__(self, bits):
        self.bits = bits

        self.p = Crypto.Util.number.getPrime(
            self.bits, randfunc=Crypto.Random.get_random_bytes)
        self.alpha = randint(0, self.p-1)
        self.a = randint(0, self.p-1)
        self.y = pow(self.alpha, self.a, self.p)
        self.k = Crypto.Util.number.getPrime(
            self.bits, randfunc=Crypto.Random.get_random_bytes)
        self.k_1 = (libnum.invmod(self.k, self.p-1))

        self.public = (self.y, self.alpha, self.p)

    def sign(self, msg):
        D = int.from_bytes(hashlib.sha256(
            msg.encode()).digest(), byteorder='big')

        r = pow(self.alpha, self.k, self.p)
        s = (D - self.alpha * r) % (self.p - 1)
        return (self.y, r, s, self.p, self.alpha, D)

    def check(self, y, r, s, p, a, m):
        left = (pow(y, r, p)*pow(r, s, p)) % p
        right = pow(a, m, p)
        print(left)
        print(right)
        if (left == right):
            return True
        return False


print("Message: %s " % msg)

eig = Elgamal(32)
message = "hello"
(y, r, s, p, a, d) = eig.sign(message)
eig.check(y, r, s, p, a, d)
