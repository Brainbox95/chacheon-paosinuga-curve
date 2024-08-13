class PaosinugaCurve:
    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b

    def add_points(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0] and P[1] != Q[1]:
            return None
        if P != Q:
            lam = ((Q[1] - P[1]) * pow(Q[0] - P[0], -1, self.p)) % self.p
        else:
            lam = ((3 * P[0]**2 + self.a) * pow(2 * P[1], -1, self.p)) % self.p
        x3 = (lam**2 - P[0] - Q[0]) % self.p
        y3 = (lam * (P[0] - x3) - P[1]) % self.p
        return (x3, y3)

    def scalar_mult(self, k, P):
        R = None
        for i in range(256):
            if (k >> i) & 1:
                R = self.add_points(R, P)
            P = self.add_points(P, P)
        return R
