#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <cstdint>

// Constants for SHA-256
const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

class SHA256 {
public:
    SHA256() { reset(); }

    void update(const uint8_t* data, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            dataBuffer[dataLength] = data[i];
            dataLength++;
            if (dataLength == 64) {
                transform();
                bitLength += 512;
                dataLength = 0;
            }
        }
    }

    void final(uint8_t hash[32]) {
        bitLength += dataLength * 8;
        dataBuffer[dataLength++] = 0x80;

        if (dataLength > 56) {
            while (dataLength < 64) {
                dataBuffer[dataLength++] = 0x00;
            }
            transform();
            dataLength = 0;
        }

        while (dataLength < 56) {
            dataBuffer[dataLength++] = 0x00;
        }

        for (int i = 7; i >= 0; --i) {
            dataBuffer[dataLength++] = (bitLength >> (i * 8)) & 0xFF;
        }
        transform();

        for (int i = 0; i < 8; ++i) {
            for (int j = 3; j >= 0; --j) {
                hash[i * 4 + (3 - j)] = (state[i] >> (j * 8)) & 0xFF;
            }
        }
    }

private:
    uint32_t state[8], dataLength;
    uint64_t bitLength;
    uint8_t dataBuffer[64];

    void reset() {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        dataLength = 0;
        bitLength = 0;
    }

    void transform() {
        uint32_t maj, ch, temp1, temp2, w[64], a, b, c, d, e, f, g, h;

        for (int i = 0; i < 16; ++i) {
            w[i] = (dataBuffer[i * 4] << 24) | (dataBuffer[i * 4 + 1] << 16) |
                   (dataBuffer[i * 4 + 2] << 8) | (dataBuffer[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = (w[i - 15] >> 7 | w[i - 15] << (32 - 7)) ^ (w[i - 15] >> 18 | w[i - 15] << (32 - 18)) ^ (w[i - 15] >> 3);
            uint32_t s1 = (w[i - 2] >> 17 | w[i - 2] << (32 - 17)) ^ (w[i - 2] >> 19 | w[i - 2] << (32 - 19)) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = (e >> 6 | e << (32 - 6)) ^ (e >> 11 | e << (32 - 11)) ^ (e >> 25 | e << (32 - 25));
            ch = (e & f) ^ (~e & g);
            temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = (a >> 2 | a << (32 - 2)) ^ (a >> 13 | a << (32 - 13)) ^ (a >> 22 | a << (32 - 22));
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
};

std::string sha256(std::ifstream& file) {
    SHA256 sha;
    std::vector<uint8_t> buffer(1024);
    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
        sha.update(buffer.data(), buffer.size());
    }
    sha.update(buffer.data(), file.gcount());

    uint8_t hash[32];
    sha.final(hash);

    std::ostringstream oss;
    for (int i = 0; i < 32; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

int main() {
    std::ifstream file("ramughanta256.txt", std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open the file.\n";
        return 1;
    }

    std::string hash = sha256(file);
    std::cout << "SHA-256 hash: " << hash << std::endl;

    return 0;
}
