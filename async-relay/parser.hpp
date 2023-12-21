#ifndef BKC_PARSER_HPP
#define BKC_PARSER_HPP

#include "llhttp.h"
#include "uv.h"

namespace bkc
{
    struct http_req_parser_t
    {
        llhttp_t parser;

    };
};

#endif