#include <cstddef>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ios>
#include <filesystem>
#include <string>
#include <vector>

#include "sha256.h"

static std::ofstream outlog("sha256_log.txt");

std::string SHA256::str()
{
    std::ostringstream ret;
    ret << std::hex << std::setfill('0') << std::setw(8)
        << A << std::setw(8) << B << std::setw(8) << C << std::setw(8)
        << D << std::setw(8) << E << std::setw(8) << F << std::setw(8)
        << G << std::setw(8) << H;

    outlog << ret.str() << '\n';

    return ret.str();
}

std::vector<std::size_t> SHA256::ints()
{
    return std::vector<std::size_t>{A,B,C,D,E,F,G,H};
}

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
    unsigned extended[64];
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

void SHA256::make_mblocks(unsigned* mblocks, unsigned char* section)
{
    for (std::size_t i = 0; i != 16; ++i)
    {
        unsigned char block[4];
        memcpy(block, &section[i*4], 4);
        mblocks[i] = get_4be(block);
    }
}

void SHA256::hash(unsigned char* message, std::size_t N)
{
    reset_state();
    unsigned mblocks[16];

    std::size_t sz = N;
    std::size_t orig = sz;
    std::size_t pos = 0;
    unsigned char* newm = new unsigned char[N];
    memcpy(newm, message, N);

    unsigned char section[64]{};
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
