#pragma warning(disable:6386)
#include <cmath>
#include <cstddef>
#include <iostream>
#include <iomanip>
#include <ios>
#include <string>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <sstream>
#include "md5.h"

using std::cout;

std::ofstream outlog("log.txt");

void MD5::reset_state()
{
    AA = A = 0x67452301;
    BB = B = 0xefcdab89;
    CC = C = 0x98badcfe;
    DD = D = 0x10325476;
}

unsigned char* make_8le(std::size_t sz)
{
    unsigned char* ret = new unsigned char[8];

    size_t adj_sz = sz * 8; // size calculated from chars, so * 8 for size in bits

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
    unsigned char* ret = new unsigned char[4]; // size in bytes

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

    delete[] aa;
    delete[] bb;
    delete[] cc;
    delete[] dd;

    return ret.str();
}

unsigned get_4le(unsigned char* bob)
{
    unsigned ret = bob[3] << 24 | bob[2] << 16 | bob[1] << 8 | bob[0];
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

        unsigned previous_F = F;
        F = AA + F + get_4le(word) + T[i];
        AA = DD;
        DD = CC;
        CC = BB;
        BB += rotleft(F, s[i]);

    }
    A += AA;
    B += BB;
    C += CC;
    D += DD;

    AA = A;
    BB = B;
    CC = C;
    DD = D;
}

void pad(unsigned char* section, size_t sz)
{
    section[sz] = 0x80;
    for (size_t i = sz + 1; i != 56; ++i)
    {
        section[i] = 0;
    }
}


std::string MD5::hash(unsigned char* message, std::size_t N)
{

    std::size_t sz = N;
    std::size_t orig = sz;
    unsigned char* newm = new unsigned char[N];
    memcpy(newm, message, N);

    unsigned char* section = new unsigned char[65] {};
    while (sz > 64)
    {
        memcpy(section, newm, 64);
        section[64] = 0;
        do_section(section);
        std::fill_n(section, 64, 0);
        sz -= 64;
        std::advance(newm, 64);
    }

    if (sz >= 56)
    {
        memcpy(section, newm, sz);
        section[sz] = 0x80;
        for (std::size_t i = sz + 1; i != 64; ++i)
        {
            section[i] = 0x00;
        }
        do_section(section);
        std::fill_n(section, 64, 0);
    }
    else
    {
        memcpy(section, newm, sz);
        pad(section, sz);
    }

    unsigned char* msg_size = make_8le(orig);
    for (std::size_t i = 56; i != 64; ++i)
    {
        section[i] = msg_size[i - 56];
    }
    do_section(section);

    delete[] section;
    delete[] message;
    delete[] msg_size;

    outlog << std::hex << A << B << C << D << '\n';

    std::string ret = hex_str(A,B,C,D);
    outlog << ret << '\n';

    reset_state();
    return ret;
}

std::string MD5::hash_file(const std::string& filename)
{
    std::basic_ifstream<unsigned char> infile(filename, std::ios_base::binary);
    std::size_t filesize = std::filesystem::file_size(std::filesystem::path(filename));
    unsigned char* message = new unsigned char[filesize];
    infile.read(message, filesize);
    return hash(message, filesize);
}

std::string MD5::hash_string(const std::string& message)
{
    std::size_t sz = message.size();
    unsigned char* umsg = new unsigned char[sz];
    memcpy(umsg, message.data(), sz);
    return hash(umsg, sz);
}
