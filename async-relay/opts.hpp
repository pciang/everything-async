#ifndef ARELAY_OPTS_HPP
#define ARELAY_OPTS_HPP

#include <cstdio>
#include <string>
#include <getopt.h>

namespace arelay
{

    struct opts_t
    {
        int port, destination_port;
        std::string destination_host;
    } opts;

    enum parse_errcode_t : int
    {
        err_parse_opts = -3,
        err_missing_opts,
        err_using_system_port,
        parse_success,
    };

    static const option PROG_LONG_OPTS[] = {
        {"port", required_argument, NULL, 'p'},
        {"destination_host", required_argument, NULL, 'H'},
        {"destination_port", required_argument, NULL, 'P'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };

    static const char *PROG_SHORT_OPTS = "p:H:P:h";

    const char *parse_errstr(enum parse_errcode_t errcode)
    {
        switch (errcode)
        {
        case err_parse_opts:
            return "error while parsing options";
        case err_missing_opts:
            return "error missing required options";
        case err_using_system_port:
            return "don't listen on system port (0-1023)";
        case parse_success:
            return "success parsing options";
        }
        return "undefined";
    }

    enum parse_errcode_t parse_opts(int argc, char *argv[])
    {
        opts.port = 0;
        opts.destination_host = "";
        opts.destination_port = 0;

        int retval;
        do
        {
            retval = getopt_long(argc, argv, PROG_SHORT_OPTS, PROG_LONG_OPTS, NULL);
            switch (retval)
            {
            case 'p':
            {
                std::string stlstr(optarg);
                opts.port = std::atoi(stlstr.c_str());
                break;
            }
            case 'H':
                opts.destination_host = optarg;
                break;
            case 'P':
            {
                std::string stlstr(optarg);
                opts.destination_port = std::atoi(stlstr.c_str());
                break;
            }
            case 'h':
            case '?':
                std::fprintf(stderr, "Usage:\n");
                std::fprintf(stderr, "  [-h | --help]\n");
                std::fprintf(stderr, "  (-p | --port)             Listen on which local port number (e.g.: 8080)\n");
                std::fprintf(stderr, "  (-H | --destination_host) Destination host (e.g.: 192.168.0.1)\n");
                std::fprintf(stderr, "  (-P | --destination_port) Destination port (e.g.: 80)\n");
                break;
            }
        } while (-1 != retval && '?' != retval);

        if ('?' == retval)
        {
            return err_parse_opts;
        }

        if (0 == opts.port || 0 == opts.destination_port || opts.destination_host.empty())
        {
            return err_missing_opts;
        }

        if (1023 >= opts.port)
        {
            return err_using_system_port;
        }

        return parse_success;
    }

};

#endif
