
#include <cmath>
#include <vector>
#include <iostream>

#include "md5.h"

using std::cout;
using std::vector;

int main()
{
    MD5 test;
    auto bob = test.hash("I have twenty two pineapples and they have characters a");
    cout << bob;
}