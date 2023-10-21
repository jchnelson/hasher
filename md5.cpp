#include <cmath>
#include <cstddef>
#include <iostream>
#include <iomanip>
#include <string>
#include <functional>
#include <fstream>
#include <sstream>
#include "md5.h"

using std::cout;

using func = std::function<unsigned(unsigned, unsigned, unsigned)>;

std::ofstream outlog("log.txt");

unsigned char* make_8be(size_t sz)
{
    unsigned char* ret = new unsigned char[8];
    ret[0] = (sz >> 56);
    ret[1] = (sz >> 48) & 255;
    ret[2] = (sz >> 40) & 255;
    ret[3] = (sz >> 32) & 255;
    ret[4] = (sz >> 24) & 255;
    ret[5] = (sz >> 16) & 255;
    ret[6] = (sz >> 8) & 255;
    ret[7] = (sz & 255);
    return ret;
}

unsigned char* make_8le(size_t sz)
{
    unsigned char* ret = new unsigned char[8];

    ret[0] = sz & 255;
    ret[1] = (sz >> 8) & 255;
    ret[2] = (sz >> 16) & 255;
    ret[3] = (sz >> 24) & 255;
    ret[4] = (sz >> 32) & 255;
    ret[5] = (sz >> 40) & 255;
    ret[6] = (sz >> 48) & 255;
    ret[7] = (sz >> 56);

    return ret;
}

unsigned* make_4le(size_t sz)
{
    unsigned* ret = new unsigned[4];

    ret[0] = sz & 255;
    ret[1] = (sz >> 8) & 255;
    ret[2] = (sz >> 16) & 255;
    ret[3] = (sz >> 24) & 255;

    return ret;
}

std::string hex_str(unsigned a, unsigned b, unsigned c, unsigned d)
{
    std::ostringstream ret;
    unsigned* aa = make_4le(a);
    unsigned* bb = make_4le(b);
    unsigned* cc = make_4le(c);
    unsigned* dd = make_4le(d);

    ret << std::hex 
        << aa[0] << aa[1] << aa[2] << aa[3]
        << bb[0] << bb[1] << bb[2] << bb[3]
        << cc[0] << cc[1] << cc[2] << cc[3]
        << dd[0] << dd[1] << dd[2] << dd[3];

    return ret.str();
}

unsigned get_4le(unsigned char* bob)
{
    unsigned ret = bob[3] << 24 | bob[2] << 16 | bob[1] << 8 | bob[0];
    return ret;
}

unsigned get_4be(unsigned char* bob)
{
    unsigned ret = bob[3] | bob[2] << 8 | bob[1] << 16 | bob[0] << 24;
    return ret;
}

unsigned rotleft(unsigned orig, unsigned amount)
{
    return (orig << amount) | (orig >> (32 - amount));
}

MD5::MD5()
{
    for (int i = 0; i != 64; ++i)
        T[i] = (unsigned(floor(pow(2, 32) * abs(sin(i + 1)))));

}

void MD5::do_section(unsigned char* section)
{

    for (int i = 0; i < 64; ++i)
    {
        unsigned F;
        unsigned g;
        if (i < 16)
        {
            F = (BB & CC) | ((~BB) & DD);
            g = i;
        }
        else if (i < 32)
        {
            F = (BB & DD) | (CC & (~DD));
            g = (5 * i + 1) % 16;
        }
        else if (i < 48)
        {
            F = BB ^ CC ^ DD;
            g = (3 * i + 5) % 16;
        }
        else
        {
            F = CC ^ (BB | (~DD));
            g = (7 * i) % 16;
        }
        unsigned char word[4]{};

        for (size_t k = 0; k != 4; ++k)
        {
            word[k] = section[(g*4) + k];
        }
        //outlog << std::dec << " operation " << std::right << std::setw(2) << i
        // << " x[k]: " << std::hex << get_4le(word) << '\n';


        unsigned previous_F = F;
        F = AA + F + get_4le(word) + T[i];
        AA = DD;
        DD = CC;
        CC = BB;
        BB += rotleft(F, s[i]);

        outlog << "A is " << std::hex << AA << " F is " << previous_F << " constant is "
            << T[i] << " message is " << get_4le(word)
            << " shift amount " << std::dec << s[i] << '\n';


        outlog << "after operation " << std::dec << i
            << " with message segment " << std::hex << get_4le(word) << '\n';
        outlog << "F was " << std::hex << F << '\n';
        outlog << AA << ' ' << BB << ' ' << CC << ' ' << DD << '\n';

    }
    A += AA;
    B += BB;
    C += CC;
    D += DD;

}

void pad(unsigned char* section, size_t sz)
{
    section[sz] = 0x80;
    for (size_t i = sz + 1; i != 56; ++i)
    {
        section[i] = 0;
    }
}

std::string MD5::hash(const std::string& message)
{

    size_t sz = message.size();

    unsigned char* section = new unsigned char[64]{};

    // next handle larger messages

    if (sz < 56)
    {
        memcpy(section, message.data(), sz);
        pad(section, sz);
        unsigned char* msg_size = make_8le(sz);
        for (size_t i = 56; i != 64; ++i)
        {
            section[i] = msg_size[i - 56];
        }
    }

    do_section(section);
    delete[] section;

    outlog << std::hex << A << B << C << D << '\n';

    return hex_str(A,B,C,D);
}