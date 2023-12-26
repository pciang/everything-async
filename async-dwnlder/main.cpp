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

    prog->outfile = 0;

    uv_loop_t *loop = uv_default_loop();
    loop->data = prog;

    memset(&prog->hint, 0, sizeof(addrinfo));
    prog->hint.ai_family = AF_INET;
    prog->hint.ai_socktype = SOCK_STREAM;
    prog->hint.ai_protocol = IPPROTO_TCP;

    int retval;

    uv_fs_t *fsreq = (uv_fs_t *)malloc(sizeof(uv_fs_t));
    if (0 != (retval = uv_fs_open(uv_default_loop(), fsreq, dwnlder::opts.outfile.c_str(), O_CREAT | O_RDWR, S_IRWXU | S_IRGRP | S_IROTH, on_attempted_fs_open)))
    {
        fprintf(stderr, "error attempting to open a file: %s\n", uv_err_name(retval));

        free(fsreq);
        return -1;
    }

    return uv_run(loop, UV_RUN_DEFAULT);
}
