#include <iostream>

#include "hasher.h"

using std::cout;

int main()
{
    cout << std::hex;

    MD5 md5;
    md5.hash_file("Requiem.mp3");
    cout << md5.str() << '\n';
    for (const auto& one_int : md5.ints())
    {
        cout << one_int << '\n';
    }

    SHA1 sha1;
    sha1.hash_string("Bob's your uncle");
    cout << sha1.str() << '\n';
    for (const auto& one_int : sha1.ints())
    {
        cout << one_int << '\n';
    }

    SHA256 sha256;
    sha256.hash_file("Requiem.mp3");
    cout << sha256.str() << '\n';
    for (const auto& one_int : sha256.ints())
    {
        cout << one_int << '\n';
    }

    SHA224 sha224;
    sha224.hash_string("Two-dollar margaritas on wednesdays!");
    cout << sha224.str() << '\n';
    for (const auto& one_int : sha224.ints())
    {
        cout << one_int << '\n';
    }

    SHA512 sha512;
    sha512.hash_file("Requiem.mp3");
    cout << sha512.str() << '\n';
    for (const auto& one_int : sha512.ints())
    {
        cout << one_int << '\n';
    }

    SHA384 sha384;
    sha384.hash_string("Two-dollar margaritas on wednesdays!");
    cout << sha384.str() << '\n';
    for (const auto& one_int : sha384.ints())
    {
        cout << one_int << '\n';
    }

    SHA512_224 sha512_224;
    sha512_224.hash_string("Bob's your uncle");
    cout << sha512_224.str() << '\n';
    for (const auto& one_int : sha512_224.ints())
    {
        cout << one_int << '\n';
    }

    SHA512_256 sha512_256;
    sha512_256.hash_string("Bob's your uncle");
    cout << sha512_256.str() << '\n';
    for (const auto& one_int : sha512_256.ints())
    {
        cout << one_int << '\n';
    }

}