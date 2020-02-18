def get_lowest_bits(n, w):
    """Returns the lowest number of bits of n."""
    mask = (1 << w) - 1
    return n & mask


class MT19937:
    """
    MT19937 Mersenne Twister RNG. Mersenne prime: 2^19937−1
    # w: word size (in number of bits)
    # n: degree of recurrence
    # m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
    # r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
    # a: coefficients of the rational normal form twist matrix
    # b, c: TGFSR(R) tempering bitmasks
    # s, t: TGFSR(R) tempering bit shifts
    # u, d, l: additional Mersenne Twister tempering bit shifts/masks
    """

    def __init__(self, seed, bits=32):
        """32-bit or 64-bit word length"""
        if bits == 32:  # Coefficients for MT19937-32
            self.w, self.n, self.m, self.r = 32, 624, 397, 31
            self.a = 0x9908B0DF
            self.u, self.d = 11, 0xFFFFFFFF
            self.s, self.b = 7, 0x9D2C5680
            self.t, self.c = 15, 0xEFC60000
            self.f = 1812433253
            self.l = 18
        elif bits == 64:  # Coefficients for MT19937-64
            self.w, self.n, self.m, self.r = 64, 312, 156, 31
            self.a = 0xB5026F5AA96619E9
            self.u, self.d = 29, 0x5555555555555555
            self.s, self.b = 17, 0x71D67FFFEDA60000
            self.t, self.c = 37, 0xFFF7EEE000000000
            self.f = 6364136223846793005
            self.l = 43

        self.mt = [0] * self.n  # state of the generator. length n array
        self.index = self.n + 1
        self.lower_mask = (1 << self.r) - 1  # 0b11111111... r times 1
        self.upper_mask = get_lowest_bits(not self.lower_mask, self.w)

        self.seed_mt(seed)

    def seed_mt(self, seed):
        """Initialize the generator from a seed"""
        self.index = self.n
        self.mt[0] = seed
        for i in range(1, self.n):  # loop over each element
            self.mt[i] = get_lowest_bits((self.f * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w - 2))) + i), self.w)

    def extract_number(self):
        """Extract a tempered value based on MT[index] calling twist() every n numbers."""
        if self.index >= self.n:
            if self.index > self.n:
                print("Generator was never seeded")
                self.seed_mt(5489)  # Alternatively, seed with constant value;
            self.twist()

        y = self.mt[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index = self.index + 1
        return get_lowest_bits(y, self.w)  # lowest w bits of (y)

    def twist(self):
        """Generate the next n values from the series x_i"""
        for i in range(self.n):
            x = (self.mt[i] & self.upper_mask) + (self.mt[(i + 1) % self.n] & self.lower_mask)
            xA = x >> 1
            if x % 2 != 0:  # lowest bit of x is 1
                xA = xA ^ self.a
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xA
        self.index = 0


if __name__ == '__main__':

    # Implement the MT19937 Mersenne Twister RNG
    # Mersenne prime: 2^19937−1
    # twisted GFSR
    # 32-bit or 64-bit word length

    for i in range(100):
        print(MT19937(i).extract_number())
    for i in range(100):
        print(MT19937(i, 64).extract_number())
