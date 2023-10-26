#include <string>
#include <filesystem>
#include <sstream>

#include "hash_algo.h"

std::string HashAlgo::hash_file(const std::string& filename)
{
    std::basic_ifstream<unsigned char> infile(filename, std::ios_base::binary);
    std::size_t filesize = std::filesystem::file_size(std::filesystem::path(filename));
    unsigned char* message = new unsigned char[filesize];
    infile.read(message, filesize);
    hash(message, filesize);
    return str();
}

std::string HashAlgo::hash_string(const std::string& message)
{
    std::size_t sz = message.size();
    unsigned char* umsg = new unsigned char[sz];
    if (sz != 0)
        memcpy(umsg, message.data(), sz);
    hash(umsg, sz);
    return str();
}