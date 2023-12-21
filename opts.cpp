#include "opts.hpp"

int main(int argc, char *argv[])
{
    enum bkc::parse_err_t retcode = bkc::parse_opts(argc, argv);
    if (bkc::parse_success != retcode)
    {
        // TODO:
        printf("%s\n", bkc::errstring(retcode));
        return -1;
    }
    else
    {
        printf("listening on port   : %d\n", bkc::opts.port);
        printf("target addr and port: %s:%d\n", bkc::opts.destination_addr.c_str(), bkc::opts.destination_port);
    }
    return 0;
}
