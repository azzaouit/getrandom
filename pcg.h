#ifndef PCG_H
#define PCG_H 

#define uint64_t unsigned long long
#define uint32_t unsigned

#define WORD_TO_BYTES(w, b)                                                    \
  do {                                                                         \
    b[0] = w & 0xff;                                                           \
    b[1] = (w >> 8);                                                           \
    b[2] = (w >> 16);                                                          \
    b[3] = (w >> 24);                                                          \
  } while (0)

#define rotr32(x, r) (x >> r | x << (-r & 31))

static uint64_t const multiplier = 6364136223846793005u;
static uint64_t const increment = 1442695040888963407u;
static uint64_t state = 0x4d595df4d0f33173;

static uint32_t pcg32(void) {
  uint64_t x = state;
  unsigned count = (unsigned)(x >> 59);
  state = x * multiplier + increment;
  x ^= x >> 18;
  return rotr32((uint32_t)(x >> 27), count);
}

static void pcgn(char *buf, unsigned n) {
  uint32_t r;
  unsigned nw = n >> 2;
  unsigned rem = n & 0x3;

  for (unsigned i = 0; i < nw; ++i, buf += 4) {
    r = pcg32();
    WORD_TO_BYTES(r, buf);
  }

  if (rem) {
    r = pcg32();
    for (unsigned i = 0; i < rem; ++i)
      buf[i] = (r >> 8 * i);
  }
}

#endif /* PCG_H */
