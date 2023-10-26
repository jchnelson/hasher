#pragma once

#include <string>
#include <vector>
#include <cstddef>

#include "hash_algo.h"

class SHA1 : public HashAlgo
{
public:
    SHA1() = default;
    std::string str();
    std::vector<std::size_t> ints();

private:
    unsigned A = 0x67452301;
    unsigned B = 0xEFCDAB89;
    unsigned C = 0x98BADCFE;
    unsigned D = 0x10325476;
    unsigned E = 0xC3D2E1F0;
    unsigned AA = A;
    unsigned BB = B;
    unsigned CC = C;
    unsigned DD = D;
    unsigned EE = E;
    void reset_state();
    void make_mblocks(unsigned*, unsigned char*);
    void do_section(unsigned* section);
    void hash(unsigned char* message, std::size_t N);

};

unsigned rotl(unsigned orig, unsigned amount);