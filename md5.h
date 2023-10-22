#pragma once
#include <string>
#include <vector>
#include <cstddef>
#include <iterator>

class MD5
{
public:
    MD5();
    std::string hash_file(const std::string&);
    std::string hash_string(const std::string&);

private:
    unsigned A = 0x67452301;
    unsigned B = 0xefcdab89;
    unsigned C = 0x98badcfe;
    unsigned D = 0x10325476;
    unsigned AA = A;
    unsigned BB = B;
    unsigned CC = C;
    unsigned DD = D;
    unsigned T[64]{};
    unsigned s[64]{
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,  6, 10, 15, 21 };
    void do_section(unsigned char*);
    std::string hash(unsigned char*, std::size_t);
    void reset_state();
};

