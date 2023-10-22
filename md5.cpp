#include <cmath>
#include <cstddef>
#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <fstream>
#include <sstream>
#include "md5.h"

using std::cout;

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

    // little endian, but first byte only has 5 bits for some reason?????
    // 0b00000001 becomes 0b00001000
    // 31 becomes 0b11111000
    // 32 is 0b00000000 0b00000001
    // 34 becomes 0b00011000 0b00000001

    // to get the original, or all the other bits ahead of it, then right shift
    // the entire number right by 3... or to reverse that:

    size_t adj_sz = sz << 3;

    ret[0] = adj_sz & 255;
    ret[1] = (adj_sz >> 8) & 255;
    ret[2] = (adj_sz >> 16) & 255;
    ret[3] = (adj_sz >> 24) & 255;
    ret[4] = (adj_sz >> 32) & 255;
    ret[5] = (adj_sz >> 40) & 255;
    ret[6] = (adj_sz >> 48) & 255;
    ret[7] = (adj_sz >> 56);

    return ret;
}

unsigned char* make_4le(size_t sz)
{
    unsigned char* ret = new unsigned char[4];

    ret[0] = sz & 255;
    ret[1] = (sz >> 8) & 255;
    ret[2] = (sz >> 16) & 255;
    ret[3] = (sz >> 24) & 255;

    return ret;
}

std::string hex_str(unsigned a, unsigned b, unsigned c, unsigned d)
{
    std::ostringstream ret;
    unsigned char* aa = make_4le(a);
    unsigned char* bb = make_4le(b);
    unsigned char* cc = make_4le(c);
    unsigned char* dd = make_4le(d);

    ret << std::hex 
        << (aa[0] >> 4) << (aa[0] & 15) << (aa[1] >> 4) << (aa[1] & 15) 
        << (aa[2] >> 4) << (aa[2] & 15) << (aa[3] >> 4) << (aa[3] & 15)
        << (bb[0] >> 4) << (bb[0] & 15) << (bb[1] >> 4) << (bb[1] & 15)
        << (bb[2] >> 4) << (bb[2] & 15) << (bb[3] >> 4) << (bb[3] & 15)
        << (cc[0] >> 4) << (cc[0] & 15) << (cc[1] >> 4) << (cc[1] & 15) 
        << (cc[2] >> 4) << (cc[2] & 15) << (cc[3] >> 4) << (cc[3] & 15)
        << (dd[0] >> 4) << (dd[0] & 15) << (dd[1] >> 4) << (dd[1] & 15)
        << (dd[2] >> 4) << (dd[2] & 15) << (dd[3] >> 4) << (dd[3] & 15);

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
    size_t orig = sz;
    std::string newm = message;

    unsigned char* section = new unsigned char[64]{};

    if (sz >= 56)
    {
        while (sz > 64)
        { 
            memcpy(section, newm.data(), 64);
            do_section(section);
            std::fill_n(section, 64, 0);
            sz -= 64;
            newm = newm.substr(64);
        }
        // we don't have a full block to process, and now
        // the padding happens

        memcpy(section, newm.data(), sz);
        section[sz] = 0x80;
        for (size_t i = sz + 1; i != 64; ++i)
        {
            section[i] = 0;
        }
        do_section(section);
        std::fill_n(section, 64, 0);
        sz = 0; // now we enter the small sz section with 0 sz
    }

    if (sz < 56)
    {
        memcpy(section, message.data(), sz);
        pad(section, sz);
        unsigned char* msg_size = make_8le(orig);
        for (size_t i = 56; i != 64; ++i)
        {
            section[i] = msg_size[i - 56];
            cout << unsigned(msg_size[i-56]);
        }
        //section[56] = 0;
        //section[57] = 1;
    }
    cout << '\n';
    do_section(section);
    delete[] section;

    outlog << std::hex << A << B << C << D << '\n';

    return hex_str(A,B,C,D);
}