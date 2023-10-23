#include <cstddef>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ios>
#include <filesystem>
#include <string>

#include "SHA512_224.h"

static std::ofstream outlog("SHA512_224_log.txt");


void SHA512_224::reset_state()
{
    AA = A = 0x8C3D37C819544DA2;
    BB = B = 0x73E1996689DCD4D6;
    CC = C = 0x1DFAB7AE32FF9C82;
    DD = D = 0x679DD514582F9FCF;
    EE = E = 0x0F6D2B697BD44DA8;
    FF = F = 0x77E36F7304C48942;
    GG = G = 0x3F9D85A86A1D36C8;
    HH = H = 0x1112E6AD91D692A1;
}

void SHA512_224::do_section(u_ll* section)
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

void SHA512_224::make_mblocks(u_ll* mblocks, unsigned char* section)
{
    for (std::size_t i = 0; i != 16; ++i)
    {
        unsigned char block[8];
        memcpy(block, &section[i * 8], 8);
        mblocks[i] = get_8be(block);
    }
}

std::string SHA512_224::hash(unsigned char* message, std::size_t N)
{
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

    std::ostringstream ret;
    ret << std::hex << std::setfill('0') << std::setw(16)
        << A << std::setw(16) << B << std::setw(16) << C << std::setw(8)
        << (D >> 32);

    outlog << ret.str() << '\n';

    reset_state();
    return ret.str();
}

std::string SHA512_224::hash_file(const std::string& filename)
{
    std::basic_ifstream<unsigned char> infile(filename, std::ios_base::binary);
    std::size_t filesize = std::filesystem::file_size(std::filesystem::path(filename));
    unsigned char* message = new unsigned char[filesize];
    infile.read(message, filesize);
    return hash(message, filesize);
}

std::string SHA512_224::hash_string(const std::string& message)
{
    std::size_t sz = message.size();
    unsigned char* umsg = new unsigned char[sz];
    if (sz != 0)
        memcpy(umsg, message.data(), sz);
    return hash(umsg, sz);
}
