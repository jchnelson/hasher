
#include <cmath>
#include <vector>
#include <iostream>

#include "hasher.h"

using std::cout;
using std::vector;

int main()
{
    //MD5 md5;
    //auto bob = md5.hash_file("Requiem.mp3");
    //cout << bob << '\n';

    //SHA1 sha1;

    //auto steve = sha1.hash_string("Bob's your uncle");
    //cout << steve << '\n';

    //SHA256 sha256;

    //auto frank = sha256.hash_file("Requiem.mp3");
    //cout << frank << '\n';

    //SHA224 sha224;

    //auto chris = sha224.hash_string("Two-dollar margaritas on wednesdays!");
    //cout << chris << '\n';

    SHA512 sha512;

    auto framb = sha512.hash_file("Requiem.mp3");
    cout << framb << '\n';

    SHA384 sha384;
    auto snert = sha384.hash_string("Two-dollar margaritas on wednesdays!");
    cout << snert << '\n';

    SHA512_224 sha512_224;
    auto qwert = sha512_224.hash_string("Bob's your uncle");
    cout << qwert << '\n';

    SHA512_256 sha512_256;
    auto qwerty = sha512_256.hash_string("Bob's your uncle");
    cout << qwerty << '\n';

}