#include <cstdio>
#include <string>

#include "uv.h"
#include "llhttp.h"

#include "main.hpp"

int main(int argc, char *argv[])
{
    if (0 != dwnlder::parse_opts(argc, argv))
    {
        return -1;
    }

    dwnlder::prog_t *prog = (dwnlder::prog_t *)malloc(sizeof(dwnlder::prog_t));
    llhttp_settings_init(&prog->settings);
    prog->settings.on_body = on_body;
    prog->settings.on_header_field = on_header_field;
    prog->settings.on_header_field_complete = on_header_field_complete;
    prog->settings.on_header_value = on_header_value;
    prog->settings.on_header_value_complete = on_header_value_complete;
    prog->settings.on_headers_complete = on_headers_complete;

    uv_cond_init(&prog->gate);
    uv_mutex_init(&prog->lock);

    uv_loop_t *loop = uv_default_loop();
    loop->data = prog;

    addrinfo hint;
    memset(&hint, 0, sizeof(addrinfo));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;

    uv_getaddrinfo_t *getaddrinfo_req = (uv_getaddrinfo_t *)malloc(sizeof(uv_getaddrinfo_t));

    std::string destin_port = std::to_string(dwnlder::opts.port);

    int retval, _;
    if (0 != (retval = uv_getaddrinfo(loop, getaddrinfo_req, on_resolved, dwnlder::opts.host.c_str(), destin_port.c_str(), &hint)))
    {
        fprintf(stderr, "error invoking uv_getaddrinfo: %s\n", uv_err_name(retval));
        return -1;
    }

    uv_tcp_t *client = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
    _ = uv_tcp_init(loop, client);

    client->data = make_composite(&prog->settings);

    uv_connect_t *connreq = (uv_connect_t *)malloc(sizeof(uv_connect_t));
    if (0 != (retval = uv_tcp_connect(connreq, client, prog->res->ai_addr, on_tcp_connected)))
    {
        fprintf(stderr, "couldn't initiate tcp connection: %s\n", uv_err_name(retval));
        return -1;
    }

    return uv_run(loop, UV_RUN_DEFAULT);
}
