#include <map>
#include <string>
#include <iostream>
#include <utility>

typedef std::map<std::string, std::string> mapper_t;

int main(int argc, char *argv[])
{
    mapper_t mapper;
    std::string test, test2;

    std::cout << "initially, test = " << test << std::endl;

    test.append(std::move(std::string("test123")));

    std::cout << "after append, test = " << test << std::endl;

    mapper[std::move(test)] = "";

    std::cout << "after mapped, test = " << test << std::endl;

    test = "Test_again";
    test2 = "world!";

    test.append(std::move(test2));

    std::cout << "after append, test  = " << test << std::endl;
    std::cout << "after append, test2 = " << test2 << std::endl;

    std::pair<mapper_t::iterator, bool> retval = mapper.emplace(mapper_t::value_type(std::move(test), std::move(test2)));

    std::cout << "after emplace, test  = " << test << std::endl;
    std::cout << "after emplace, test2 = " << test2 << std::endl;

    std::cout << retval.first->first << ", " << retval.first->second << std::endl;

    return 0;
}