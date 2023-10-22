
#include <cmath>
#include <vector>
#include <iostream>

#include "md5.h"

using std::cout;
using std::vector;

int main()
{
    MD5 test;
    auto bob = test.hash_file("Requiem.mp3");
    cout << bob;
}