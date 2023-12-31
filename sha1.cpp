#include <cstddef>
#include <iostream>
#include <ios>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <vector>
#include <string>

#include "sha1.h"

static std::ofstream outlog("sha_log.txt");

std::string SHA1::str()
{
    std::ostringstream ret;
    ret << std::hex << std::setfill('0') << std::setw(8) << A 
        << std::setw(8) << B << std::setw(8) << C
        << std::setw(8) << D << std::setw(8) << E;

    outlog << ret.str() << '\n';

    return ret.str();
}

std::vector<std::size_t> SHA1::ints()
{
    return std::vector<std::size_t>{A,B,C,D,E};
}

void SHA1::reset_state()
{
    AA = A = 0x67452301;
    BB = B = 0xEFCDAB89;
    CC = C = 0x98BADCFE;
    DD = D = 0x10325476;
    EE = E = 0xC3D2E1F0;
}

unsigned char* make_8be(std::size_t sz)
{
    sz *= 8; // calculated from char, *= 8 is size in bits

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

unsigned get_4be(unsigned char* bob)
{
    unsigned ret = bob[0] << 24 | bob[1] << 16 | bob[2] << 8 | bob[3];
    return ret;
}

void SHA1::do_section(unsigned* section)
{
    unsigned extended[80];
    memcpy(extended, section, 64);
    for (int i = 0; i < 80; ++i)
    {
        unsigned F;
        unsigned k;
        if (i < 20)
        {
            F = (BB & CC) | ((~BB) & DD);
            k = 0x5A827999;
        }
        else if (i < 40)
        {
            F = BB ^ CC ^ DD;
            k = 0x6ED9EBA1;
        }
        else if (i < 60)
        {
            F = (BB & CC) | (BB & DD) | (CC & DD);
            k = 0x8F1BBCDC;
        }
        else
        {
            F = BB ^ CC ^ DD;
            k = 0xCA62C1D6;
        }
        unsigned debugvar = (section[i - 3] ^ section[i - 8] ^ 
                             section[i - 14] ^ section[i - 16]);
        extended[i] = i < 16 ? extended[i] : (rotl((extended[i - 3] ^
            extended[i - 8] ^ extended[i - 14] ^ extended[i - 16]), 1));

        unsigned temp = rotl(AA, 5) + F + EE + k + extended[i];
        EE = DD;
        DD = CC;
        CC = rotl(BB, 30);
        BB = AA;
        AA = temp;

        //outlog << "after operation " << std::dec << i
        //    << " with message segment " << std::hex << extended[i] << '\n';
        //outlog << std::hex << AA << ' ' << BB << ' ' << CC << ' ' 
        //    << DD << ' ' << EE << '\n';
    }
    AA = A += AA;
    BB = B += BB;
    CC = C += CC;
    DD = D += DD;
    EE = E += EE;
}

void SHA1::make_mblocks(unsigned* mblocks, unsigned char* section)
{
    for (std::size_t i = 0; i != 16; ++i)
    {
        unsigned char block[4];
        memcpy(block, &section[i*4], 4);
        mblocks[i] = get_4be(block);
    }
}

void SHA1::hash(unsigned char* message, std::size_t N)
{
    reset_state();
    unsigned mblocks[16];

    std::size_t sz = N;
    std::size_t orig = sz;
    std::size_t pos = 0;
    unsigned char* newm = new unsigned char[N];
    memcpy(newm, message, N);

    unsigned char section[64];
    while (sz > 64)
    {
        make_mblocks(mblocks, &newm[pos]);
        do_section(mblocks);
        sz -= 64;
        pos += 64;
    }

    if (sz >= 56)
    {
        memcpy(section, &newm[pos], sz);
        section[sz] = 0x80;
        for (std::size_t i = sz + 1; i != 64; ++i)
        { 
            section[i] = 0x00;
        }
        make_mblocks(mblocks, section);
        do_section(mblocks);
    }
    else
    {
        memcpy(section, &newm[pos], sz);
        section[sz] = 0x80;
        for (size_t i = sz + 1; i != 56; ++i)
        {
            section[i] = 0;
        }
    }
    unsigned char* msg_size = make_8be(orig);
    for (std::size_t i = 56; i != 64; ++i)
    {
        section[i] = msg_size[i - 56];
    }
    make_mblocks(mblocks, section);
    do_section(mblocks);

    delete[] message;
    delete[] newm;
    delete[] msg_size;
}
