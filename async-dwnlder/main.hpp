#ifndef DWNLDER_MAIN_HPP
#define DWNLDER_MAIN_HPP

#include <cstdio>
#include <cstring>
#include <string>
#include <map>
#include <utility>

#include "getopt.h"

#include "uv.h"
#include "llhttp.h"

typedef std::map<std::string, std::string> header_t;

namespace dwnlder
{

    const char *TEMPLATE_GET = "GET {path} HTTP/1.1\r\n"
                               "Host: {host}\r\n"
                               "User-Agent: async-dwnlder\r\n"
                               "Accept: *\r\n"
                               "Accept-Encoding: identity\r\n"
                               "Connection: close\r\n"
                               "Cache-Control: no-cache\r\n"
                               "\r\n";

    struct opts_t
    {
        int port;
        std::string host, path, outfile;
    } opts;

    const char *OPTSTRING = "H:p:P:o:h";

    const char *HELPSTR =
        "[-h]  display help\n"
        "(-H)  host (e.g.: upload.wikimedia.org)\n"
        "(-p)  port (e.g.: 80)\n"
        "(-P)  resource path (e.g.: /somewhere/afile.txt)\n"
        "(-o)  saved file name (e.g.: ./afile.txt)\n";

    int parse_opts(int argc, char *argv[])
    {
        // TODO: maybe use a url parser

        int retval;

        do
        {
            retval = getopt(argc, argv, OPTSTRING);

            switch (retval)
            {
            case 'H':
                opts.host = optarg;
                break;
            case 'p':
                opts.port = std::stoi(std::string(optarg));
                break;
            case 'P':
                opts.path = optarg;
                break;
            case 'o':
                opts.outfile = optarg;
                break;
            case 'h':
            case '?':
                fprintf(stderr, HELPSTR);
                break;
            }

        } while (-1 != retval && '?' != retval);

        if ('?' == retval)
        {
            return -1;
        }

        if (0 == opts.port || opts.host.empty() || opts.path.empty() || opts.outfile.empty())
        {
            fprintf(stderr, "missing required arguments\n\n");
            fprintf(stderr, HELPSTR);
            return -1;
        }

        return 0;
    }

    std::string prepare_httpreq()
    {
        std::string getreq = TEMPLATE_GET;

        return std::move(getreq.replace(getreq.find("{host}"), 6, opts.host)
                             .replace(getreq.find("{path}"), 6, opts.path));
    }

    struct prog_t
    {
        addrinfo *res;
        uv_cond_t gate;
        uv_mutex_t lock;
        uv_file outfile;
        llhttp_settings_t settings;
    };

    struct composite_parser_t
    {
        llhttp_t parser;
        std::string partial;
        header_t headers;
        header_t::iterator pheader;
    };
};

dwnlder::prog_t *get_prog()
{
    return (dwnlder::prog_t *)uv_default_loop()->data;
}

dwnlder::prog_t *get_prog(uv_loop_t *loop)
{
    return (dwnlder::prog_t *)loop->data;
}

dwnlder::composite_parser_t *make_composite(const llhttp_settings_t *settings)
{
    dwnlder::composite_parser_t *composite = (dwnlder::composite_parser_t *)malloc(sizeof(dwnlder::composite_parser_t));
    composite->partial = std::move(std::string());
    composite->headers = std::move(header_t());
    composite->pheader = composite->headers.begin();
    llhttp_init(&composite->parser, HTTP_RESPONSE, settings);
    return composite;
}

dwnlder::composite_parser_t *get_composite(llhttp_t *parser)
{
    return (dwnlder::composite_parser_t *)parser;
}

dwnlder::composite_parser_t *get_composite(uv_stream_t *stream)
{
    return (dwnlder::composite_parser_t *)stream->data;
}

int on_header_field(llhttp_t *parser, const char *at, size_t length)
{
    get_composite(parser)->partial.append(at, at + length);
    return 0;
}

int on_header_field_complete(llhttp_t *parser)
{
    dwnlder::composite_parser_t *composite = get_composite(parser);
    std::pair<header_t::iterator, bool> retval = composite->headers.emplace(header_t::value_type(std::move(composite->partial), ""));
    composite->pheader = retval.first;
    return 0;
}

int on_header_value(llhttp_t *parser, const char *at, size_t length)
{
    get_composite(parser)->partial.append(at, at + length);
    return 0;
}

int on_header_value_complete(llhttp_t *parser)
{
    dwnlder::composite_parser_t *composite = get_composite(parser);
    composite->pheader->second = std::move(composite->partial);
    return 0;
}

void on_attempted_fs_open(uv_fs_t *req)
{
    if (0 > req->result)
    {
        fprintf(stderr, "couldn't open the file: %s\n", uv_err_name(req->result));

        free(req);
        return;
    }

    dwnlder::prog_t *prog = get_prog(req->loop);
    prog->outfile = req->result;

    // signal the other side that the wait is over
    uv_cond_signal(&prog->gate);

    free(req);
}

int on_headers_complete(llhttp_t *parser)
{
    if (HTTP_STATUS_OK != llhttp_get_status_code(parser))
    {
        fprintf(stderr, "response is not OK\n");
        return -1;
    }

    int retval;

    uv_fs_t *fsreq = (uv_fs_t *)malloc(sizeof(uv_fs_t));
    if (0 != (retval = uv_fs_open(uv_default_loop(), fsreq, dwnlder::opts.outfile.c_str(), O_CREAT, O_RDWR, on_attempted_fs_open)))
    {
        fprintf(stderr, "error attempting to open a file: %s\n", uv_err_name(retval));

        free(fsreq);
        return -1;
    }

    return 0;
}

void destruct_fs_wreq(uv_fs_t *req)
{
    uv_buf_t *wbuf = (uv_buf_t *)req->data;

    free(wbuf->base);
    free(wbuf);
    free(req);
}

void on_fs_written(uv_fs_t *req)
{
    if (0 > req->result)
    {
        fprintf(stderr, "error writing into outfile: %s\n", uv_err_name(req->result));
    }

    destruct_fs_wreq(req);
}

int on_body(llhttp_t *parser, const char *at, size_t length)
{
    int retval;

    dwnlder::prog_t *prog = get_prog();

    // wait indefinitely until outfile is actually opened
    uv_cond_wait(&prog->gate, &prog->lock);

    uv_buf_t *filewbuf = (uv_buf_t *)malloc(sizeof(uv_buf_t));
    filewbuf->base = (char *)malloc(length);
    filewbuf->len = length;
    memcpy(filewbuf->base, at, length);

    uv_fs_t *filewreq = (uv_fs_t *)malloc(sizeof(uv_fs_t));
    filewreq->data = filewbuf;

    if (0 != (retval = uv_fs_write(uv_default_loop(), filewreq, prog->outfile, filewbuf, 1, -1, on_fs_written)))
    {
        fprintf(stderr, "error attempting to write into outfile: %s\n", uv_err_name(retval));

        destruct_fs_wreq(filewreq);
        return -1;
    }

    return 0;
}

void on_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res)
{
    get_prog(req->loop)->res = res;

    free(req);
}

void common_alloc(uv_handle_t *_, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void on_shutdown(uv_shutdown_t *req, int status)
{
    if (0 != status && UV_ECANCELED != status)
    {
        fprintf(stderr, "error shutting down for some reason: %s\n", uv_err_name(status));
    }

    free(req->handle);
    free(req);
}

void on_closed(uv_handle_t *handle)
{
    free(handle);
}

void on_data_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    int retval;

    if (0 >= nread)
    {
        switch (nread)
        {
        case 0: // do nothing
            break;
        case UV_EOF:
        {
            uv_shutdown_t *shutreq = (uv_shutdown_t *)malloc(sizeof(uv_shutdown_t));

            if (0 != (retval = uv_shutdown(shutreq, stream, on_shutdown)))
            {
                fprintf(stderr, "error couldn't initiate shutdown %p: %s\n", (void *)stream, uv_err_name(retval));
                free(shutreq);
            }

            break;
        }
        default:
            fprintf(stderr, "error reading stream %p: %s\n", (void *)stream, uv_err_name(nread));
            break;
        }

        if (NULL != buf->base)
        {
            free(buf->base);
        }

        return;
    }

    dwnlder::composite_parser_t *composite = get_composite(stream);

    if (0 != (retval = llhttp_execute(&composite->parser, buf->base, nread)))
    {
        fprintf(stderr, "error parsing http response: %d\n", retval);

        uv_read_stop(stream);
        uv_close((uv_handle_t *)stream, on_closed);
    }

    free(buf->base);
}

void destruct_httpreq_wreq(uv_write_t *req)
{
    uv_buf_t *wbuf = (uv_buf_t *)req->data;

    free(wbuf->base);
    free(wbuf);
    free(req);
}

void on_httpreq_sent(uv_write_t *req, int status)
{
    if (0 != status)
    {
        fprintf(stderr, "error couldn't send httpreq: %s\n", uv_err_name(status));
    }
    else
    {
        int _ = uv_read_start(req->handle, common_alloc, on_data_read);
    }

    destruct_httpreq_wreq(req);
}

void on_tcp_connected(uv_connect_t *req, int status)
{
    if (0 != status)
    {
        fprintf(stderr, "couldn't connect: %s\n", uv_err_name(status));

        free(req);
        return;
    }

    int retval;

    uv_stream_t *stream = req->handle;
    uv_write_t *wreq = (uv_write_t *)malloc(sizeof(uv_write_t));
    uv_buf_t *wbuf = (uv_buf_t *)malloc(sizeof(uv_buf_t));

    std::string httpreq = dwnlder::prepare_httpreq();

    wbuf->base = (char *)malloc(httpreq.length());
    wbuf->len = httpreq.length();

    wreq->data = wbuf; // don't free directly from req->bufs

    memcpy(wbuf->base, httpreq.c_str(), httpreq.length());

    if (0 != (retval = uv_write(wreq, stream, wbuf, 1, on_httpreq_sent)))
    {
        fprintf(stderr, "error couldn't initiate write %p: %s\n", (void *)stream, uv_err_name(retval));

        destruct_httpreq_wreq(wreq);
        return;
    }

    free(req);
}

#endif
