#ifndef BKC_OPTS_HPP
#define BKC_OPTS_HPP

#include <cstdio>
#include <string>
#include <getopt.h>

namespace bkc
{

    struct opts_t
    {
        std::string destination_addr;
        int port, destination_port;
    } opts;

    enum opts_name_t : int
    {
        opt_port = 0x7fffffff - 25,
        opt_destination_addr,
        opt_destination_port,
        opt_help,
    };

    enum parse_err_t : int
    {
        err_parse_opts = -2,
        err_missing_opts,
        parse_success,
    };

    static const option PROG_LONG_OPTS[] = {
        {"port", required_argument, NULL, opt_port},
        {"destination_addr", required_argument, NULL, opt_destination_addr},
        {"destination_port", required_argument, NULL, opt_destination_port},
        {"help", no_argument, NULL, opt_help},
        {0, 0, 0, 0},
    };

    static const char *PROG_SHORT_OPTS = "p:a:P:h";

    const char *errstring(enum parse_err_t errcode)
    {
        switch (errcode)
        {
        case err_parse_opts:
            return "error while parsing options";
        case err_missing_opts:
            return "error missing required options";
        case parse_success:
            return "success parsing options";
        }
        return "undefined";
    }

    enum parse_err_t parse_opts(int argc, char *argv[])
    {
        int retval;
        do
        {
            retval = getopt_long(argc, argv, PROG_SHORT_OPTS, PROG_LONG_OPTS, NULL);
            switch (retval)
            {
            case 'p':
            case opt_port:
            {
                std::string stlstr(optarg);
                opts.port = std::atoi(stlstr.c_str());
                break;
            }
            case 'a':
            case opt_destination_addr:
                opts.destination_addr = optarg;
                break;
            case 'P':
            case opt_destination_port:
            {
                std::string stlstr(optarg);
                opts.destination_port = std::atoi(stlstr.c_str());
                break;
            }
            case 'h':
            case opt_help:
            case '?':
            case -1:
                std::fprintf(stderr, "Usage:\n");
                std::fprintf(stderr, "  [-h | --help]\n");
                std::fprintf(stderr, "  (-p | --port)             Listen on which local port number (e.g.: 8080)\n");
                std::fprintf(stderr, "  (-a | --destination_addr) Destination host (e.g.: 192.168.0.1)\n");
                std::fprintf(stderr, "  (-P | --destination_port) Destination port (e.g.: 80)\n");
                break;
            }
        } while (-1 != retval && '?' != retval);

        if ('?' == retval)
        {
            return err_parse_opts;
        }

        if (opts.port == 0 || opts.destination_port == 0 || opts.destination_addr.empty())
        {
            return err_missing_opts;
        }

        return parse_success;
    }

};

#endif
