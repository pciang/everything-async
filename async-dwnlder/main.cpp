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

    {
        FILE *outfile = fopen("/Users/p.peter/ssl-key.log", "w");
        fclose(outfile);
    }

    dwnlder::prog_t *prog = (dwnlder::prog_t *)malloc(sizeof(dwnlder::prog_t));
    llhttp_settings_init(&prog->settings);
    prog->settings.on_body = on_body;
    prog->settings.on_header_field = on_header_field;
    prog->settings.on_header_field_complete = on_header_field_complete;
    prog->settings.on_header_value = on_header_value;
    prog->settings.on_header_value_complete = on_header_value_complete;
    prog->settings.on_headers_complete = on_headers_complete;

    prog->tls_ctx = init_tls(dwnlder::opts.host.c_str());

    prog->outfile = 0;

    uv_loop_t *loop = uv_default_loop();
    loop->data = prog;

    memset(&prog->hint, 0, sizeof(addrinfo));
    prog->hint.ai_family = AF_INET;
    prog->hint.ai_socktype = SOCK_STREAM;
    prog->hint.ai_protocol = IPPROTO_TCP;

    prog->composite = make_composite(&prog->settings);

    int retval;

    uv_fs_t *fsreq = (uv_fs_t *)malloc(sizeof(uv_fs_t));
    if (0 != (retval = uv_fs_open(uv_default_loop(), fsreq, dwnlder::opts.outfile.c_str(), O_CREAT | O_RDWR, S_IRWXU | S_IRGRP | S_IROTH, on_attempted_fs_open)))
    {
        fprintf(stderr, "error attempting to open a file: %s\n", uv_err_name(retval));

        free(fsreq);
        return -1;
    }

    retval = uv_run(loop, UV_RUN_DEFAULT);

    if (0 == retval && ishttps())
    // We need to flush out leftover buffers in the SSL session
    {
        int nleftover;
        char buf[65536];
        do
        {
            nleftover = SSL_read(prog->tls_ctx->tls, buf, sizeof(buf));

            if (0 != (retval = llhttp_execute(&prog->composite->parser, buf, nleftover)))
            {
                fprintf(stderr, "error parsing last chunk of response: %d\n", retval);
                return retval;
            }
        } while (nleftover > 0);

        return uv_run(loop, UV_RUN_DEFAULT);
    }

    return retval;
}
