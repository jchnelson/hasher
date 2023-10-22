
#include <cmath>
#include <vector>
#include <iostream>

#include "md5.h"
#include "sha1.h"

using std::cout;
using std::vector;

int main()
{
    MD5 md5;
    auto bob = md5.hash_file("Requiem.mp3");
    cout << bob << '\n';

    SHA1 sha1;

    auto steve = sha1.hash_file("Requiem.mp3");
    cout << steve;
}