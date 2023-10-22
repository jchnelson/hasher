
#include <cmath>
#include <vector>
#include <iostream>

#include "md5.h"

using std::cout;
using std::vector;

int main()
{
    MD5 test;
    auto bob = test.hash("Intentionally created message of fifty six bitty bitties");
    cout << bob;
}