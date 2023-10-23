#include <cstddef>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ios>
#include <filesystem>
#include <string>

#include "sha256.h"

static std::ofstream outlog("sha256_log.txt");



unsigned rotr(unsigned orig, unsigned amount)
{
    return orig >> amount | orig << (32 - amount);
}

void SHA256::reset_state()
{
    AA = A = 0x6a09e667;
    BB = B = 0xbb67ae85;
    CC = C = 0x3c6ef372;
    DD = D = 0xa54ff53a;
    EE = E = 0x510e527f;
    FF = F = 0x9b05688c;
    GG = G = 0x1f83d9ab;
    HH = H = 0x5be0cd19;
}

void SHA256::do_section(unsigned* section)
{
    unsigned* extended = new unsigned[64];
    memcpy(extended, section, 64); // original 16 segments
    for (int i = 0; i < 64; ++i)
    {
        unsigned s0 = i < 16 ? 0 : rotr(extended[i - 15], 7) ^ 
            rotr(extended[i - 15], 18) ^ (extended[i - 15] >> 3);
        unsigned s1 = i < 16 ? 0 : rotr(extended[i - 2], 17) ^ 
            rotr(extended[i - 2], 19) ^ (extended[i - 2] >> 10);
            
        extended[i] = i < 16 ? extended[i] : extended[i-16] + s0 
            + extended[i-7] + s1;

        unsigned S0 = rotr(AA, 2) ^ rotr(AA, 13) ^ rotr(AA, 22);
        unsigned S1 = rotr(EE, 6) ^ rotr(EE, 11) ^ rotr(EE, 25);
        unsigned ch = (EE & FF) ^ ((~EE) & GG);
        unsigned temp1 = HH + S1 + ch + k[i] + extended[i];
        unsigned maj = (AA & BB) ^ (AA & CC) ^ (BB & CC);
        unsigned temp2 = S0 + maj;

        HH = GG;
        GG = FF;
        FF = EE;
        EE = DD + temp1;
        DD = CC;
        CC = BB;
        BB = AA;
        AA = temp1 + temp2;

        /*outlog << "after operation " << std::dec << i
            << " with message segment " << std::hex << extended[i] << '\n';
        outlog << std::hex << AA << ' ' << BB << ' ' << CC << ' ' 
            << DD << ' ' << EE << ' ' << FF << ' ' << GG << ' ' << HH << '\n';*/
    }
    AA = A += AA;
    BB = B += BB;
    CC = C += CC;
    DD = D += DD;
    EE = E += EE;
    FF = F += FF;
    GG = G += GG;
    HH = H += HH;
}

void SHA256::make_mblocks(unsigned* mblocks, unsigned char*& section)
{
    for (std::size_t i = 0; i != 16; ++i)
    {
        unsigned char block[4]{};
        memcpy(block, section, 4);
        std::advance(section, 4);
        mblocks[i] = get_4be(block);
    }
}

std::string SHA256::hash(unsigned char* message, std::size_t N)
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
    ret << std::hex << A << B << C << D << E << F << G << H;

    outlog << ret.str() << '\n';

    reset_state();
    return ret.str();
}

std::string SHA256::hash_file(const std::string& filename)
{
    std::basic_ifstream<unsigned char> infile(filename, std::ios_base::binary);
    std::size_t filesize = std::filesystem::file_size(std::filesystem::path(filename));
    unsigned char* message = new unsigned char[filesize];
    infile.read(message, filesize);
    return hash(message, filesize);
}

std::string SHA256::hash_string(const std::string& message)
{
    std::size_t sz = message.size();
    unsigned char* umsg = new unsigned char[sz] {};
    if (sz != 0)
        memcpy(umsg, message.data(), sz);
    return hash(umsg, sz);
}
