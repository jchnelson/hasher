
#include <cmath>
#include <vector>
#include <iostream>

#include "md5.h"
#include "sha1.h"
#include "sha256.h"

using std::cout;
using std::vector;

int main()
{
    MD5 md5;
    auto bob = md5.hash_file("Requiem.mp3");
    cout << bob << '\n';

    SHA1 sha1;

    auto steve = sha1.hash_string("Bob's your uncle");
    cout << steve << '\n';

    SHA256 sha256;

    auto frank = sha256.hash_file("Requiem.mp3");
    cout << frank;
}