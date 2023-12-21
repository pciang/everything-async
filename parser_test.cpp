#include <vector>
#include <string>
#include "llhttp.h"

int on_req_begin(llhttp_t *parser)
{
    printf("parser begins\n");
    return 0;
}

int on_req_headers_complete(llhttp_t *parser)
{
    if (HTTP_GET == llhttp_get_method(parser))
    {
        printf("got a GET request\n");
        return 1;
    }
    printf("got something else\n");
    return 0;
}

int on_req_complete(llhttp_t *parser)
{
    printf("this parser completed\n");
    return 0;
}

int main(int argc, char *argv[])
{
    std::vector<std::string> http_requests{
        "test",                                                                               // incorrect
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",                                          // correct
        "GET / HTT",                                                                          // partial
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\nGET /",                                     // first complete second partial
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n", // first complete second complete
    };

    llhttp_settings_t settings;
    llhttp_settings_init(&settings);

    settings.on_message_begin = on_req_begin;
    settings.on_headers_complete = on_req_headers_complete;
    settings.on_message_complete = on_req_complete;

    for (std::string http_request : http_requests)
    {
        printf("request:\n%s\n", http_request.c_str());

        llhttp_t parser;
        llhttp_init(&parser, HTTP_REQUEST, &settings);

        enum llhttp_errno retval = llhttp_execute(&parser, http_request.c_str(), http_request.length());
        printf("retval = %d\n", retval);
        if (HPE_OK == retval)
        {
            printf("request successfully parsed\n");
        }
        else
        {
            printf("error string: %s\n", llhttp_errno_name(retval));
            printf("parser reason: %s\n", parser.reason);
        }
    }

    return 0;
}
