#pragma once
#include <string>

class HashAlgo
{
public:
    HashAlgo() = default;
    virtual std::string hash_string(const std::string&) = 0;
    virtual std::string hash_file(const std::string&) = 0;
    virtual ~HashAlgo() = default;
};
