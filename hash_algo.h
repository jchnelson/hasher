#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <cstddef>


class HashAlgo
{
public:
    HashAlgo() = default;
    virtual ~HashAlgo() = default;
    std::string hash_string(const std::string& message);
    std::string hash_file(const std::string& filename);
    virtual std::string str() = 0;
    virtual std::vector<std::size_t> ints() = 0;


protected:
    virtual void hash(unsigned char*, std::size_t) = 0;
};
