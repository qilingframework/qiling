#include <iostream>
#include <cstdlib>

/*
 * Test simple try..catch.
 */
void test1()
{
    std::cout << "y";

    try {
        std::cout << "y";
        throw (unsigned int)0x12345678;
        std::cout << "n";
    }
    catch(unsigned int n) {
        n;
        std::cout << "y";
    }

    std::cout << "y";
}

/*
 * Test simple try..catch with throw.
 */
void test2()
{
    std::cout << "y";

    try {
        std::cout << "y";
        throw (unsigned int)0x12345679;
        std::cout << "n";
    }
    catch (unsigned int n) {
        n;
        if (n == 0x12345679) {
            std::cout << "y";
        }
        else {
            std::cout << "n";
        }
    }

    std::cout << "y";
}

/*
 * Test nested try..catch with throw.
 */
void test3()
{
    std::cout << "y";

    try {
        std::cout << "y";

        try {
            std::cout << "y";
            throw (unsigned int)0x1234567A;
            std::cout << "n";
        }
        catch (unsigned int n) {
            n;
            if (n == 0x1234567A) {
                std::cout << "y";
            }
            else {
                std::cout << "n";
            }
        }
        
        std::cout << "y";
    }
    catch (unsigned int n) {
        n;
        std::cout << "n";
    }

    std::cout << "y";
}

int main()
{
    /*
     * For this program, all subtests successful will print:
     * - 14 'y'
     * - 0 'n'
     */

    test1();
    test2();
    test3();
}
