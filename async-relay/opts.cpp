#include "opts.hpp"

int main(int argc, char *argv[])
{
    arelay::parse_errcode_t retcode = arelay::parse_opts(argc, argv);

    if (arelay::parse_success != retcode)
    {
        printf("%s\n", arelay::parse_errstr(retcode));
        return -1;
    }
    else
    {
        printf("listening on port   : %d\n", arelay::opts.port);
        printf("target addr and port: %s:%d\n", arelay::opts.destination_host.c_str(), arelay::opts.destination_port);
    }
    return 0;
}
