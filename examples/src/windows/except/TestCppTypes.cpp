#include <iostream>

struct TestStruct {
    float q;
};

class TestClass {
public:
    int x, y;
    virtual ~TestClass() {
        std::cout << "TestClass destructor, GOOD" << std::endl;
    };
    void yyy() {
        std::cout << "REALLY GOOD" << std::endl;
    }
};

class Something {
public:
    char z;
    virtual ~Something() {
        std::cout << "Something destructor, GOOD" << std::endl;
    };
    virtual void zzz() {
        std::cout << "BAD" << std::endl;
    };
};

class TestClass2 : public TestClass, public Something {
public:
    int z;
    virtual ~TestClass2() {
        std::cout << "TestClass2 destructor, GOOD" << std::endl;
    };
    virtual void zzz() {
        std::cout << "GOOD" << std::endl;
    };
};

int main()
{
    /*
     * For this program, all subtests successful will print:
     * - 12 'GOOD'
     * - 0 'BAD'
     */

    int x = 5;
    TestClass p;
    TestStruct s;

    std::cout << typeid(x).name() << std::endl;
    if (strcmp(typeid(x).name(), "int") == 0) {
        std::cout << "typeid(x) is int, GOOD" << std::endl;
    }
    else {
        std::cout << "typeid(x) is NOT int, BAD" << std::endl;
    }

    std::cout << typeid(p).name() << std::endl;
    if (strcmp(typeid(p).name(), "class TestClass") == 0) {
        std::cout << "typeid(p) is \"class TestClass\", GOOD" << std::endl;
    }
    else {
        std::cout << "typeid(p) is NOT \"class TestClass\", BAD" << std::endl;
    }

    std::cout << typeid(s).name() << std::endl;
    if (strcmp(typeid(s).name(), "struct TestStruct") == 0) {
        std::cout << "typeid(s) is \"struct TestStruct\", GOOD" << std::endl;
    }
    else {
        std::cout << "typeid(s) is NOT \"struct TestStruct\", BAD" << std::endl;
    }

    std::cout << "Reached virtual methods and dynamic_cast test. GOOD" << std::endl;

    TestClass2* kz = new TestClass2;

    Something* ks = static_cast<Something*>(kz);

    ks->zzz();

    TestClass* pk = dynamic_cast<TestClass*>(ks);

    pk->yyy();

    std::cout << "Reached virtual destructor test. GOOD" << std::endl;

    delete pk;

    std::cout << "Finished all tests. GOOD" << std::endl;
}
