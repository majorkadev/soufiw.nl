#include "internal_fixes.h"
#include "HookFn.h"
#include <cstdint>
#include <memory.h>
#include <immintrin.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sig0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sig1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

const uint32_t K[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


inline uint32_t swap_endian(uint32_t val)
{
    return ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) | ((val >> 8) & 0xff00) | ((val << 24) & 0xff000000);
};

static void __cdecl sha256_trash(__m128i* a1, __m128i* a2, unsigned int a3, int a4)
{
    uint32_t* state_ptr = (uint32_t*)a1;
    uint8_t* data = (uint8_t*)a2;

    uint32_t A = state_ptr[0], B = state_ptr[1], C = state_ptr[2], D = state_ptr[3];
    uint32_t E = state_ptr[4], F = state_ptr[5], G = state_ptr[6], H = state_ptr[7];

    uint32_t W[64];

    for (unsigned int block = 0; block < a3; block += 64)
    {
        const uint8_t* curr_block = data + block;

        for (int i = 0; i < 16; ++i)
        {
            uint32_t val;
            memcpy(&val, curr_block + i * 4, 4);
            W[i] = (a4 == 1) ? swap_endian(val) : val;
        };

        for (int i = 16; i < 64; ++i)
            W[i] = sig1(W[i - 2]) + W[i - 7] + sig0(W[i - 15]) + W[i - 16];

        uint32_t a = A, b = B, c = C, d = D, e = E, f = F, g = G, h = H;

        for (int i = 0; i < 64; ++i)
        {
            uint32_t t1 = h + SIG1(e) + CH(e, f, g) + K[i] + W[i];
            uint32_t t2 = SIG0(a) + MAJ(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        };

        A += a; B += b; C += c; D += d;
        E += e; F += f; G += g; H += h;
    };

    state_ptr[0] = A; state_ptr[1] = B; state_ptr[2] = C; state_ptr[3] = D;
    state_ptr[4] = E; state_ptr[5] = F; state_ptr[6] = G; state_ptr[7] = H;
};

void fix_sha256()
{
    HookFn((PVOID)0x41EBB510, sha256_trash, 0);
};