#include <cstddef>
#include <fstream>
#include <iostream>
#include <ios>
#include <filesystem>
#include <string>

#include "sha256.h"



unsigned rotright(unsigned orig, unsigned amount)
{

}

void SHA256::reset_state()
{

}

void SHA256::do_section(unsigned* section)
{

}

std::string SHA256::hash(unsigned char* message, std::size_t N)
{

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
