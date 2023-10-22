#pragma once

#include <string>
#include <cstddef>


class SHA1
{
public:
    SHA1() = default;
    std::string hash_string(const std::string&);
    std::string hash_file(const std::string&);

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
    void do_section(unsigned* section);
    std::string hash(unsigned char* message, std::size_t N);

};

unsigned rotleft(unsigned orig, unsigned amount);