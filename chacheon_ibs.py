import hashlib
import random

from paosinuga_curve import PaosinugaCurve

class ChaCheongIBS:
    def __init__(self):
        self.curve = PaosinugaCurve(
            p=7,
            a=2,
            b=3
        )
        self.G = (1, 2)
        self.n = 23
        self.master_key = self.generate_master_key()

    def generate_master_key(self):
        return random.randint(1, self.n - 1)

    def extract_private_key(self, identity):
        h = int.from_bytes(hashlib.sha256(identity.encode()).digest(), 'big')
        return (self.master_key * h) % self.n

    def sign(self, private_key, message):
        k = random.randint(1, self.n - 1)
        R = self.curve.scalar_mult(k, self.G)
        r = R[0] % self.n
        h = int.from_bytes(hashlib.sha256(message.encode() + str(r).encode()).digest(), 'big')
        s = (k + private_key * h) % self.n
        return (r, s)

    def verify(self, public_key, message, signature):
        r, s = signature
        h = int.from_bytes(hashlib.sha256(message.encode() + str(r).encode()).digest(), 'big')
        w = pow(s, -1, self.n)
        u1 = (h * w) % self.n
        u2 = (r * w) % self.n
        X = self.curve.add_points(
            self.curve.scalar_mult(u1, self.G),
            self.curve.scalar_mult(u2, public_key)
        )
        if X is None:
            return False
        return r == X[0] % self.n
