import math

def calc_bp(n, k):
    return math.exp((-k * (k - 1)) / (2 * n))
