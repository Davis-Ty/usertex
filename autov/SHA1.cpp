/*
	100% free public domain implementation of the SHA-1 algorithm
	by Dominik Reichl <dominik.reichl@t-online.de>
	Web: http://www.dominik-reichl.de/

	Version 1.6 - 2005-02-07 (thanks to Howard Kapustein for patches)
	- You can set the endianness in your files, no need to modify the
	  header file of the CSHA1 class any more
	- Aligned data support
	- Made support/compilation of the utility functions (ReportHash
	  and HashFile) optional (useful, if bytes count, for example in
	  embedded environments)

	Version 1.5 - 2005-01-01
	- 64-bit compiler compatibility added
	- Made variable wiping optional (define SHA1_WIPE_VARIABLES)
	- Removed unnecessary variable initializations
	- ROL32 improvement for the Microsoft compiler (using _rotl)

	======== Test Vectors (from FIPS PUB 180-1) ========

	SHA1("abc") =
		A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D

	SHA1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
		84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1

	SHA1(A million repetitions of "a") =
		34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
*/

#include "SHA1.h"
#include <cstring>
#include <cstdio>
#include <stdexcept>

#ifdef SHA1_UTILITY_FUNCTIONS
#define SHA1_MAX_FILE_BUFFER 8000
#endif

// Rotate x bits to the left
#ifndef ROL32
#ifdef _MSC_VER
#define ROL32(_val32, _nBits) _rotl(_val32, _nBits)
#else
#define ROL32(_val32, _nBits) (((_val32) << (_nBits)) | ((_val32) >> (32 - (_nBits))))
#endif
#endif

#ifdef SHA1_LITTLE_ENDIAN
#define SHABLK0(i) (m_block->l[i] = \
    (ROL32(m_block->l[i], 24) & 0xFF00FF00) | (ROL32(m_block->l[i], 8) & 0x00FF00FF))
#else
#define SHABLK0(i) (m_block->l[i])
#endif

#define SHABLK(i) (m_block->l[i & 15] = ROL32(m_block->l[(i + 13) & 15] ^ m_block->l[(i + 8) & 15] \
    ^ m_block->l[(i + 2) & 15] ^ m_block->l[i & 15], 1))

// SHA-1 rounds
#define _R0(v, w, x, y, z, i) { z += ((w & (x ^ y)) ^ y) + SHABLK0(i) + 0x5A827999 + ROL32(v, 5); w = ROL32(w, 30); }
#define _R1(v, w, x, y, z, i) { z += ((w & (x ^ y)) ^ y) + SHABLK(i) + 0x5A827999 + ROL32(v, 5); w = ROL32(w, 30); }
#define _R2(v, w, x, y, z, i) { z += (w ^ x ^ y) + SHABLK(i) + 0x6ED9EBA1 + ROL32(v, 5); w = ROL32(w, 30); }
#define _R3(v, w, x, y, z, i) { z += (((w | x) & y) | (w & x)) + SHABLK(i) + 0x8F1BBCDC + ROL32(v, 5); w = ROL32(w, 30); }
#define _R4(v, w, x, y, z, i) { z += (w ^ x ^ y) + SHABLK(i) + 0xCA62C1D6 + ROL32(v, 5); w = ROL32(w, 30); }

CSHA1::CSHA1() : m_block((SHA1_WORKSPACE_BLOCK *)m_workspace) {
    Reset();
}

CSHA1::~CSHA1() {
    Reset();
}

void CSHA1::Reset() {
    m_state[0] = 0x67452301;
    m_state[1] = 0xEFCDAB89;
    m_state[2] = 0x98BADCFE;
    m_state[3] = 0x10325476;
    m_state[4] = 0xC3D2E1F0;

    m_count[0] = 0;
    m_count[1] = 0;
}

void CSHA1::Transform(uint32_t *state, uint8_t *buffer) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    std::memcpy(m_block, buffer, 64);

    // Perform SHA-1 transformations
    for (int i = 0; i < 80; ++i) {
        if (i < 20) {
            _R0(a, b, c, d, e, i);
        } else if (i < 40) {
            _R1(a, b, c, d, e, i);
        } else if (i < 60) {
            _R2(a, b, c, d, e, i);
        } else {
            _R3(a, b, c, d, e, i);
        }
    }

    // Add the working vars back into state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

#ifdef SHA1_WIPE_VARIABLES
    a = b = c = d = e = 0;
#endif
}

void CSHA1::Update(uint8_t *data, uint32_t len) {
    uint32_t i, j;

    j = (m_count[0] >> 3) & 63;

    if ((m_count[0] += len << 3) < (len << 3)) {
        m_count[1]++;
    }

    m_count[1] += (len >> 29);

    if ((j + len) > 63) {
        i = 64 - j;
        std::memcpy(&m_buffer[j], data, i);
        Transform(m_state, m_buffer);

        for (; i + 63 < len; i += 64) {
            Transform(m_state, &data[i]);
        }

        j = 0;
    } else {
        i = 0;
    }

    std::memcpy(&m_buffer[j], &data[i], len - i);
}

#ifdef SHA1_UTILITY_FUNCTIONS
bool CSHA1::HashFile(const char *filename) {
    FILE *file = std::fopen(filename, "rb");
    if (!file) {
        throw std::runtime_error("Could not open file for reading");
    }

    uint8_t data[SHA1_MAX_FILE_BUFFER];
    size_t bytesRead;

    while ((bytesRead = std::fread(data, 1, SHA1_MAX_FILE_BUFFER, file)) != 0) {
        if (std::ferror(file)) {
            std::fclose(file);
            throw std::runtime_error("Error reading from file");
        }
        Update(data, static_cast<uint32_t>(bytesRead));
    }

    std::fclose(file);
    return true;
}
#endif

// Unit testing using Google Test
#include "gtest/gtest.h"

TEST(SHA1Test, TestHashFile) {
    CSHA1 sha1;
    EXPECT_NO_THROW(sha1.HashFile("test.txt")); // Assuming "test.txt" exists
    
}
