#include <cstddef>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ios>
#include <filesystem>
#include <string>
#include <vector>

#include "sha512.h"

static std::ofstream outlog("SHA512_log.txt");

std::string SHA512::str()
{
    std::ostringstream ret;
    ret << std::hex << std::setfill('0') << std::setw(16)
        << A << std::setw(16) << B << std::setw(16) << C << std::setw(16)
        << D << std::setw(16) << E << std::setw(16) << F << std::setw(16)
        << G << std::setw(16) << H;

    outlog << ret.str() << '\n';

    return ret.str();
}

std::vector<std::size_t> SHA512::ints()
{
    return std::vector<std::size_t>{A,B,C,D,E,F,G,H};
}


u_ll rotr64(u_ll orig, u_ll amount)
{
    return orig >> amount | orig << (64 - amount);
}

unsigned char* make_16be(std::size_t sz)
{
    sz *= 8;     // calculated from char, *= 8 is size in bits

    unsigned char* ret = new unsigned char[16];
    for (size_t i = 0; i != 8; ++i)
        ret[i] = 0x00;
    ret[8] = (sz >> 56);
    ret[9] = (sz >> 48) & 255;
    ret[10] = (sz >> 40) & 255;
    ret[11] = (sz >> 32) & 255;
    ret[12] = (sz >> 24) & 255;
    ret[13] = (sz >> 16) & 255;
    ret[14] = (sz >> 8) & 255;
    ret[15] = (sz & 255);
    return ret;
}

u_ll get_8be(unsigned char* bob)
{
    u_ll ret = u_ll(bob[0]) << 56 | u_ll(bob[1]) << 48 | u_ll(bob[2]) << 40 |
        u_ll(bob[3]) << 32 | u_ll(bob[4]) << 24 | u_ll(bob[5]) << 16 |
        u_ll(bob[6]) << 8 | bob[7];
    return ret;
}

void SHA512::reset_state()
{
    AA = A = 0x6a09e667f3bcc908;
    BB = B = 0xbb67ae8584caa73b;
    CC = C = 0x3c6ef372fe94f82b;
    DD = D = 0xa54ff53a5f1d36f1;
    EE = E = 0x510e527fade682d1;
    FF = F = 0x9b05688c2b3e6c1f;
    GG = G = 0x1f83d9abfb41bd6b;
    HH = H = 0x5be0cd19137e2179;
}

void SHA512::do_section(u_ll* section)
{
    u_ll extended[80]{};
    memcpy(extended, section, 128); // original 16 segments
    for (int i = 0; i < 80; ++i)
    {
        u_ll s0 = i < 16 ? 0 : rotr64(extended[i - 15], 1) ^
            rotr64(extended[i - 15], 8) ^ (extended[i - 15] >> 7);
        u_ll s1 = i < 16 ? 0 : rotr64(extended[i - 2], 19) ^
            rotr64(extended[i - 2], 61) ^ (extended[i - 2] >> 6);

        extended[i] = i < 16 ? extended[i] : extended[i - 16] + s0
            + extended[i - 7] + s1;

        u_ll S0 = rotr64(AA, 28) ^ rotr64(AA, 34) ^ rotr64(AA, 39);
        u_ll S1 = rotr64(EE, 14) ^ rotr64(EE, 18) ^ rotr64(EE, 41);
        u_ll ch = (EE & FF) ^ ((~EE) & GG);
        u_ll temp1 = HH + S1 + ch + k[i] + extended[i];
        u_ll maj = (AA & BB) ^ (AA & CC) ^ (BB & CC);
        u_ll temp2 = S0 + maj;

        HH = GG;
        GG = FF;
        FF = EE;
        EE = DD + temp1;
        DD = CC;
        CC = BB;
        BB = AA;
        AA = temp1 + temp2;

        //outlog << "after operation " << std::dec << i
        //    << " with message segment " << std::hex << extended[i] << '\n';
        //outlog << std::hex << AA << ' ' << BB << ' ' << CC << ' '
        //    << DD << '\n' << EE << ' ' << FF << ' ' << GG << ' ' << HH << '\n';
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

void SHA512::make_mblocks(u_ll* mblocks, unsigned char* section)
{
    for (std::size_t i = 0; i != 16; ++i)
    {
        unsigned char block[8];
        memcpy(block, &section[i * 8], 8);
        mblocks[i] = get_8be(block);
    }
}

void SHA512::hash(unsigned char* message, std::size_t N)
{
    reset_state();
    u_ll mblocks[16];

    std::size_t sz = N;
    std::size_t orig = sz;
    std::size_t pos = 0;
    unsigned char* newm = new unsigned char[N];
    memcpy(newm, message, N);

    unsigned char section[128]{};
    while (sz > 128)
    {
        make_mblocks(mblocks, &newm[pos]);
        do_section(mblocks);
        sz -= 128;
        pos += 128;
    }
    if (sz >= 112)
    {
        memcpy(section, &newm[pos], sz);

        section[sz] = 0x80;
        for (std::size_t i = sz + 1; i != 128; ++i)
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
        for (size_t i = sz + 1; i != 112; ++i)
        {
            section[i] = 0;
        }
    }
    unsigned char* msg_size = make_16be(orig);
    for (std::size_t i = 112; i != 128; ++i)
    {
        section[i] = msg_size[i - 112];
    }
    make_mblocks(mblocks, section);
    do_section(mblocks);

    delete[] message;
    delete[] newm;
    delete[] msg_size;

}
