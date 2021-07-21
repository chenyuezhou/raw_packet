/* Copyright (C) Chenyue Zhou (zcy.chenyue.zhou@gmail.com) */
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/tcp.h>

#include "raw_socket.h"
#include "ip_packet.h"
#include "tcp_packet.h"
#include "lib/checksum.h"

config_t config;
static const char prog_doc[] = "Fake a TCP packet";
static const char args_doc[] = "TYPE";
static const struct argp_option opts[] = {
    { "source", 'S', "ENDPOINT", 0, "Specify source enpoint" },
    { "dest", 'D', "ENDPOINT", 0, "Specify dest endpoint" },
    { "ack", 'a', "ACK", 0, "Specify tcp acknowledgement number" },
    { "seq", 's', "SEQ", 0, "Specify tcp sequence number" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
    {},
};

static inline int tcp_type_strtoi(const char *type) {
    if (!strcasecmp(type, "ACK"))
        return TCP_FLAG_ACK;
    if (!strcasecmp(type, "SYN"))
        return TCP_FLAG_SYN;
    if (!strcasecmp(type, "RST"))
        return TCP_FLAG_RST;

    return -1;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    config_t *cfg = state->input;
    char *endpoint, *port;
    long tmp;

    switch (key) {
        case 'S':
            endpoint = arg;
            port = strchr(arg, ':');
            if (port == NULL)
                goto endpoint_error;

            errno = 0;
            tmp = strtol(port, NULL, 10);
            if (errno || tmp < 0) {
                goto endpoint_error;
            }

            endpoint[(*port) - (*endpoint)] = '\0';
            cfg->saddr = inet_addr(endpoint);
            if (cfg->saddr == INADDR_NONE)
                goto endpoint_error;

            cfg->source = htons(from32to16(tmp));
            break;
        case 'D':
            endpoint = arg;
            port = strchr(arg, ':');
            if (port == NULL)
                goto endpoint_error;

            errno = 0;
            tmp = strtol(port, NULL, 10);
            if (errno || tmp < 0) {
                goto endpoint_error;
            }

            endpoint[(*port) - (*endpoint)] = '\0';
            cfg->daddr = inet_addr(endpoint);
            if (cfg->daddr == INADDR_NONE)
                goto endpoint_error;

            cfg->dest = htons(from32to16(tmp));
            break;
endpoint_error:
            fprintf(stderr, "Invalid endpoint: %s\n", arg);
            argp_usage(state);
            break;
        case 'a':
            errno = 0;
            tmp = strtol(arg, NULL, 10);
            if (errno || tmp < 0) {
                fprintf(stderr, "Invalid acknowledgement: %s\n. %s", arg,
                        strerror(errno));
                argp_usage(state);
            }

            cfg->ack = tmp;
            break;
        case 's':
            errno = 0;
            tmp = strtol(arg, NULL, 10);
            if (errno || tmp < 0) {
                fprintf(stderr, "Invalid sequence: %s\n. %s", arg,
                        strerror(errno));
                argp_usage(state);
            }

            cfg->seq = tmp;
            break;
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        case ARGP_KEY_ARG:
            tmp = tcp_type_strtoi(arg);
            if (tmp == -1) {
                fprintf(stderr, "Invalid type: %s\n", arg);
                argp_usage(state);
                break;
            }

            if (cfg->type == -1) {
                cfg->type = tmp;
            } else {
                /* TODO support multiple types */
                cfg->type |= tmp;
            }
            break;
        case ARGP_KEY_END:
            if (cfg->type == -1) {
                fprintf(stderr, "Need specify packet type (-t SYN)\n");
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc, char **argv) {
    int sock, size, offset, flags, err;
    ssize_t n;
    void *buffer;
    struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = prog_doc,
        .args_doc = args_doc,
    };

    config.source = htons(8080);
    config.dest = htons(8081);
    config.saddr = inet_addr("127.0.0.1");
    config.daddr = inet_addr("127.0.0.1");
    config.type = -1;

    err = argp_parse(&argp, argc, argv, 0, NULL, &config);
    if (err)
        return err;

    tcp_four_tuple_t ftuple = {
        .saddr = config.saddr,
        .daddr = config.daddr,
        .source = config.source,
        .dest = config.dest,
    };

    struct sockaddr_in peer = {
        .sin_family = AF_INET,
        .sin_port = config.dest,
        .sin_addr.s_addr = config.daddr,
    };

    if ((sock = socket(PF_INET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        perror("socket(AF_INET, SOCK_RAW, htons(ETH_P_IP)) failed.");
        exit(EXIT_FAILURE);
    }

    flags = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &flags, sizeof(flags)) == -1) {
        perror("setsockopt(IP_HDRINCL) failed.");
        exit(EXIT_FAILURE);
    }

    /* create buffer */
    buffer = malloc(MAX_FRAME);
    size = sizeof(struct tcphdr);
    /* parse ip packet */
    offset = parser_ip_packet(buffer, config.saddr, config.daddr, size);
    /* parse tcp packet */
    offset += parser_tcp_packet(buffer + offset, "", 0, &ftuple, config.type);
    /* send to target */
    n = sendto(sock, buffer, offset, 0, (struct sockaddr *) &peer,
               sizeof(struct sockaddr_in));
    if (n == -1)
        perror("sendto() failed.");

    printf("send success\n");
    close(sock);

    return 0;
}
