#include <cstddef>
#include <iterator>
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>


#include "sha1.h"

std::ofstream shalog("sha_log.txt");

void SHA1::reset_state()
{
    AA = A; // = 0x67452301;
    BB = B; // = 0xEFCDAB89;
    CC = C; // = 0x98BADCFE;
    DD = D; // = 0x10325476;
    EE = E; // = 0xC3D2E1F0;
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
    unsigned* extended = new unsigned[80];
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
        extended[i] = i < 16 ? extended[i] : (rotleft((extended[i - 3] ^
            extended[i - 8] ^ extended[i - 14] ^ extended[i - 16]), 1));

        unsigned temp = rotleft(AA, 5) + F + EE + k + extended[i];
        EE = DD;
        DD = CC;
        CC = rotleft(BB, 30);
        BB = AA;
        AA = temp;

        //shalog << "after operation " << std::dec << i
        //    << " with message segment " << std::hex << extended[i] << '\n';
        //shalog << std::hex << AA << ' ' << BB << ' ' << CC << ' ' 
        //    << DD << ' ' << EE << '\n';


    }
    AA = A += AA;
    BB = B += BB;
    CC = C += CC;
    DD = D += DD;
    EE = E += EE;
}

void make_mblocks(unsigned* mblocks, unsigned char*& section)
{
    for (std::size_t i = 0; i != 16; ++i)
    {
        unsigned char block[4]{};
        memcpy(block, section, 4);
        std::advance(section, 4);
        mblocks[i] = get_4be(block);
    }
}

std::string SHA1::hash(unsigned char* message, std::size_t N)
{



    unsigned* mblocks = new unsigned[16];

    std::size_t sz = N;
    std::size_t orig = sz;
    unsigned char* newm = new unsigned char[N];
    unsigned char* newm_todelete = newm;
    memcpy(newm, message, N);

    unsigned char* section = new unsigned char[64] {};
    unsigned char* section_todelete = section;
    while (sz > 64)
    {
        make_mblocks(mblocks, newm);
        do_section(mblocks);
        sz -= 64;
    }

    if (sz >= 56)
    {
        memcpy(section, newm, sz);

        section[sz] = 0x80;
        for (std::size_t i = sz + 1; i != 64; ++i)
        { 
            section[i] = 0x00;
        }
        make_mblocks(mblocks, section);
        delete[] section_todelete;
        section = new unsigned char[64];
        section_todelete = section;
        do_section(mblocks);
    }
    else
    {
        memcpy(section, newm, sz);
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

    delete[] section_todelete;
    delete[] message;
    delete[] newm_todelete;
    delete[] msg_size;
    delete[] mblocks;

    std::ostringstream ret;
    ret << std::hex << A << B << C << D << E;

    shalog << ret.str() << '\n';

    reset_state();
    return ret.str();
}

std::string SHA1::hash_file(const std::string& filename)
{
    std::basic_ifstream<unsigned char> infile(filename, std::ios_base::binary);
    std::size_t filesize = std::filesystem::file_size(std::filesystem::path(filename));
    unsigned char* message = new unsigned char[filesize];
    infile.read(message, filesize);
    return hash(message, filesize);
}

std::string SHA1::hash_string(const std::string& message)
{
    std::size_t sz = message.size();
    unsigned char* umsg = new unsigned char[sz]{};
    if (sz != 0)
        memcpy(umsg, message.data(), sz);
    return hash(umsg, sz);
}
