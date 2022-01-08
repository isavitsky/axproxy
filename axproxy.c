/*
 * Tiny TCP<-->AX.25 proxy server
 *
 * Author: Krzysztof Kliś <krzysztof.klis@gmail.com>
 * Fixes and improvements: Jérôme Poulin <jeromepoulin@gmail.com>
 * IPv6 support: 04/2019 Rafael Ferrari <rafaelbf@hotmail.com>
 * AX.25 support: 02/2020 Ivan Savitsky <UR5VIB>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version with the following modification:
 *
 * As a special exception, the copyright holders of this library give you
 * permission to link this library with independent modules to produce an
 * executable, regardless of the license terms of these independent modules,
 * and to copy and distribute the resulting executable under terms of your choice,
 * provided that you also meet, for each linked independent module, the terms
 * and conditions of the license of that module. An independent module is a
 * module which is not derived from or based on this library. If you modify this
 * library, you may extend this exception to your version of the library, but
 * you are not obligated to do so. If you do not wish to do so, delete this
 * exception statement from your version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#ifdef USE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include <netinet/in.h>

#include <netax25/ax25.h>
#include <netax25/axlib.h>
#include <netax25/axconfig.h>

#include <stdbool.h>
#include <err.h>

#define BUF_SIZE 16384

#define READ  0
#define WRITE 1

#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define CLIENT_SOCKET_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define CLIENT_CONNECT_ERROR -7
#define CREATE_PIPE_ERROR -8
#define BROKEN_PIPE_ERROR -9
#define SYNTAX_ERROR -10

#define paclen_def 256

typedef enum {UNDEF = 0, TCP = 1, AX25 = 2} wmode_t;

int check_ipversion(char * address);
int create_socket(int port, char *axport);
void sigchld_handler(int signal);
void sigterm_handler(int signal);
void server_loop();
void handle_client(int client_sock, struct sockaddr_storage client_addr);
void forward_data(int source_sock, int destination_sock, char *message);
void forward_data_ext(int source_sock, int destination_sock, char *cmd);
int create_connection();
int parse_options(int argc, char *argv[]);
void plog(int priority, const char *format, ...);

int server_sock, client_sock, remote_sock, remote_port = 0;
int connections_processed = 0;
char *bind_addr, *remote_host, *cmd_in, *cmd_out, *ax25_port;
bool foreground = FALSE;
bool use_syslog = FALSE;
wmode_t mode = UNDEF;

#define BACKLOG 20 // how many pending connections queue will hold

/* Program start */
int main(int argc, char *argv[]) {
    int local_port;
    pid_t pid;

    bind_addr = NULL;

    local_port = parse_options(argc, argv);

    if (local_port < 0) {

        printf("Tiny TCP<-->AX.25 proxy server\n");
        printf("Syntax for TCP listening: %s [-b bind_ip] -l bind_port -h remote_call -p ax25_port [-i \"input parser\"] [-o \"output parser\"] [-f (stay in foreground)] [-s (use syslog)]\n", argv[0]);
        printf("Syntax for AX.25 listening: %s [-B bind_call] -L ax25_port -H remote_host -P remote_port [-i \"input parser\"] [-o \"output parser\"] [-f (stay in foreground)] [-s (use syslog)]\n", argv[0]);
        return local_port;
    }

    if (use_syslog)
        openlog("proxy", LOG_PID, LOG_DAEMON);

    if ((server_sock = create_socket(local_port, ax25_port)) < 0) { // start server
        plog(LOG_CRIT, "Cannot run server: %m");
        return server_sock;
    }

    signal(SIGCHLD, sigchld_handler); // prevent ended children from becoming zombies
    signal(SIGTERM, sigterm_handler); // handle KILL signal

    if (foreground) {
        server_loop();
    } else {
        switch(pid = fork()) {
            case 0: // deamonized child
                server_loop();
                break;
            case -1: // error
                plog(LOG_CRIT, "Cannot daemonize: %m");
                return pid;
            default: // parent
                close(server_sock);
        }
    }

    if (use_syslog)
        closelog();

    return EXIT_SUCCESS;
}

/* Parse command line options */
int parse_options(int argc, char *argv[]) {
    int c, local_port = 0;


    ax25_port = NULL;
    bind_addr = NULL;
    while ((c = getopt(argc, argv, "b:B:l:L:h:H:p:P:i:o:fs")) != -1) {
        switch(c) {
            case 'l':
                if ( mode == UNDEF || mode == TCP ) {
                    local_port = atoi(optarg);
                    mode = TCP;
                }
                else return SYNTAX_ERROR;
                break;
            case 'b':
                if ( mode == UNDEF || mode == TCP ) {
                    bind_addr = optarg;
                    mode = TCP;
                }
                else return SYNTAX_ERROR;
                break;
            case 'h':
                if ( mode == UNDEF || mode == TCP ) {
                    remote_host = optarg;
                    mode = TCP;
                }
                else return SYNTAX_ERROR;
                break;
            case 'p':
                if ( mode == UNDEF || mode == TCP ) {
                    ax25_port = optarg;
                    mode = TCP;
                }
                else return SYNTAX_ERROR;
                break;
            case 'L':
                if ( mode == UNDEF || mode == AX25 ) {
                    ax25_port = optarg;
                    mode = AX25;
                }
                else return SYNTAX_ERROR;
                break;
            case 'B':
                if ( mode == UNDEF || mode == AX25 ) {
                    bind_addr = optarg;
                    mode = AX25;
                }
                else return SYNTAX_ERROR;
                break;
            case 'H':
                if ( mode == UNDEF || mode == AX25 ) {
                    remote_host = optarg;
                    mode = AX25;
                }
                else return SYNTAX_ERROR;
                break;
            case 'P':
                if ( mode == UNDEF || mode == AX25 ) {
                    remote_port = atoi(optarg);
                    mode = AX25;
                }
                else return SYNTAX_ERROR;
                break;
            case 'i':
                cmd_in = optarg;
                break;
            case 'o':
                cmd_out = optarg;
                break;
            case 'f':
                foreground = TRUE;
                break;
            case 's':
                use_syslog = TRUE;
                break;
        }
    }

    if ( mode == TCP ) {
        if (local_port && remote_host && ax25_port) {
            return local_port;
        } else {
            return SYNTAX_ERROR;
        }
    }

    if ( mode == AX25 ) {
        if (ax25_port && remote_host && remote_port) {
            return 0;
        } else {
            return SYNTAX_ERROR;
        }
    }

    return SYNTAX_ERROR;
}

int check_ipversion(char * address)
{
/* Check for valid IPv4 or Iv6 string. Returns AF_INET for IPv4, AF_INET6 for IPv6 */

    struct in6_addr bindaddr;

    if (inet_pton(AF_INET, address, &bindaddr) == 1) {
         return AF_INET;
    } else {
        if (inet_pton(AF_INET6, address, &bindaddr) == 1) {
            return AF_INET6;
        }
    }
    return 0;
}

/* Create server socket */
int create_socket(int port, char *axport) {
    int server_sock;

    server_sock = SERVER_SOCKET_ERROR;

    if ( mode == TCP ) {
        int optval = 1;
        int validfamily=0;
        struct addrinfo hints, *res=NULL;
        char portstr[12];

        memset(&hints, 0x00, sizeof(hints));
        server_sock = -1;

        hints.ai_flags    = AI_NUMERICSERV;   /* numeric service number, not resolve */
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        /* prepare to bind on specified numeric address */
        if (bind_addr != NULL) {
            /* check for numeric IP to specify IPv6 or IPv4 socket */
            if (validfamily = check_ipversion(bind_addr)) {
                 hints.ai_family = validfamily;
                 hints.ai_flags |= AI_NUMERICHOST; /* bind_addr is a valid numeric ip, skip resolve */
            }
        } else {
            /* if bind_address is NULL, will bind to IPv6 wildcard */
            hints.ai_family = AF_INET6; /* Specify IPv6 socket, also allow ipv4 clients */
            hints.ai_flags |= AI_PASSIVE; /* Wildcard address */
        }

        sprintf(portstr, "%d", port);

        /* Check if specified socket is valid. Try to resolve address if bind_address is a hostname */
        if (getaddrinfo(bind_addr, portstr, &hints, &res) != 0) {
            return CLIENT_RESOLVE_ERROR;
        }

        if ((server_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
            return SERVER_SOCKET_ERROR;
        }


        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
            return SERVER_SETSOCKOPT_ERROR;
        }

        if (bind(server_sock, res->ai_addr, res->ai_addrlen) == -1) {
            close(server_sock);
            return SERVER_BIND_ERROR;
        }

        if (listen(server_sock, BACKLOG) < 0) {
            return SERVER_LISTEN_ERROR;
        }

        if (res != NULL)
            freeaddrinfo(res);
    }

    if ( mode == AX25 ) {
        struct full_sockaddr_ax25 addr;

        bzero((char *) &addr, sizeof(struct full_sockaddr_ax25));

        addr.fsa_ax25.sax25_family = AF_AX25;
        addr.fsa_ax25.sax25_ndigis = 1;
        ax25_aton_entry(bind_addr, (char *)&addr.fsa_ax25.sax25_call);

        if (ax25_config_load_ports() == 0) {
            err(1, "Cannot load AX.25 ports");
            return CLIENT_RESOLVE_ERROR;
        }

        char* ax25port = (char*) ax25_config_get_addr(axport);
        if ( ax25port == NULL ) {
            err(1, "Port %s not found", axport);
            return CLIENT_RESOLVE_ERROR;
        }
        ax25_aton_entry( ax25port, addr.fsa_digipeater[0].ax25_call);

        if ((server_sock = socket(AF_AX25, SOCK_SEQPACKET, 0)) < 0) {
            return SERVER_SOCKET_ERROR;
        }

        if (bind(server_sock, (struct sockaddr *)&addr, sizeof(struct full_sockaddr_ax25)) == -1) {
            close(server_sock);
            return SERVER_BIND_ERROR;
        }

        if (listen(server_sock, BACKLOG) < 0) {
            return SERVER_LISTEN_ERROR;
        }
    }

    return server_sock;
}

/* Send log message to stderr or syslog */
void plog(int priority, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

    if (use_syslog)
        vsyslog(priority, format, ap);
    else {
        vfprintf(stderr, format, ap);
        fprintf(stderr, "\n");
    }

    va_end(ap);
}

/* Update systemd status with connection count */
void update_connection_count()
{
#ifdef USE_SYSTEMD
    sd_notifyf(0, "STATUS=Ready. %d connections processed.\n", connections_processed);
#endif
}

/* Handle finished child process */
void sigchld_handler(int signal) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* Handle term signal */
void sigterm_handler(int signal) {
    close(client_sock);
    close(server_sock);
    exit(0);
}

/* Main server loop */
void server_loop() {
    struct sockaddr_storage client_addr;
    socklen_t addrlen = sizeof(client_addr);

#ifdef USE_SYSTEMD
    sd_notify(0, "READY=1\n");
#endif

    while (TRUE) {
        update_connection_count();
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);
        if (fork() == 0) { // handle client connection in a separate process
            close(server_sock);
            handle_client(client_sock, client_addr);
            exit(0);
        } else
            connections_processed++;

        close(client_sock);
    }

}


/* Handle client connection */
void handle_client(int client_sock, struct sockaddr_storage client_addr)
{
    char *message;

    message = mmap(NULL, sizeof(char), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if ( message == MAP_FAILED ) {
        perror("mmap");
        exit(1);
    }

    if ((remote_sock = create_connection()) < 0) {
        plog(LOG_ERR, "Cannot connect to host: %m");
        goto cleanup;
    }

    if (fork() == 0) { // a process forwarding data from client to remote socket
        if (cmd_out) {
            forward_data_ext(client_sock, remote_sock, cmd_out);
        } else {
            forward_data(client_sock, remote_sock, message);
        }
        exit(0);
    }

    if (fork() == 0) { // a process forwarding data from remote socket to client
        if (cmd_in) {
            forward_data_ext(remote_sock, client_sock, cmd_in);
        } else {
            forward_data(remote_sock, client_sock, message);
        }
        exit(0);
    }

cleanup:
    close(remote_sock);
    close(client_sock);
}

/* Forward data between sockets */
void forward_data(int source_sock, int destination_sock, char *message) {

    // move to non-blocking mode for write()
    int flags = fcntl(destination_sock, F_GETFL, 0);
    if (fcntl(destination_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("socket");
        close(source_sock);
        close(destination_sock);
        return;
    }

    int s_type;
    int s_length = sizeof( int );
    int paclen = 0;

    // Pick the correct write() buffer size for destination socket
    getsockopt( destination_sock, SOL_SOCKET, SO_TYPE, &s_type, &s_length );
    if ( s_type == SOCK_SEQPACKET ) { // AX.25
        paclen = ax25_config_get_paclen(ax25_port);
        paclen = (paclen > 0) ? paclen : paclen_def;
    }
    else {// TCP
        paclen = BUF_SIZE; // keep it less than 64K
    }

    int x=0;
    ssize_t n;
    fd_set read_fd;
    char buffer[BUF_SIZE];
    struct timeval to;

    while (1) {
        FD_ZERO(&read_fd);
        FD_SET(source_sock, &read_fd);
        to.tv_sec = 1;
        to.tv_usec = 0;
        n = 0;
        x = select(source_sock + 1, &read_fd, NULL, NULL, &to);
        if ( x < 0 ) { // error in read_fd
            break;
        }
        if ( *message != 0 ) { // shutdown flag from the sibling process
            break;
        }
        if (FD_ISSET(source_sock, &read_fd)) {
            n = read(source_sock, buffer, BUF_SIZE);
            if ( n <= 0 ) { // EOF or error
                *message=1; // set shutdown flag for the sibling process
                break;
            }
        }

        int offset = 0;
        int ret;
        while (offset != n) {
            int len = (n-offset > paclen) ? paclen : n-offset;

/* kludge here */
//if ( s_type == SOCK_SEQPACKET ) {
//    usleep(10000);
//}
            ret = write(destination_sock, buffer+offset, len); // send data to output socket
            if (ret == -1) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    usleep(100000);
                    continue;
                }
                break;
            }
            offset += ret;
        }
/* kludge here */
//if ( s_type == SOCK_SEQPACKET ) {
//    usleep(1000000);
//}
    }

    if (n < 0) {
        plog(LOG_ERR, "read: %m");
        exit(BROKEN_PIPE_ERROR);
    }

    shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
    close(destination_sock);

    shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
    close(source_sock);
}

/* Forward data between sockets through external command */
void forward_data_ext(int source_sock, int destination_sock, char *cmd) {
    char buffer[BUF_SIZE];
    int n, i, pipe_in[2], pipe_out[2];

    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) { // create command input and output pipes
        plog(LOG_CRIT, "Cannot create pipe: %m");
        exit(CREATE_PIPE_ERROR);
    }

    if (fork() == 0) {
        dup2(pipe_in[READ], STDIN_FILENO); // replace standard input with input part of pipe_in
        dup2(pipe_out[WRITE], STDOUT_FILENO); // replace standard output with output part of pipe_out
        close(pipe_in[WRITE]); // close unused end of pipe_in
        close(pipe_out[READ]); // close unused end of pipe_out
        n = system(cmd); // execute command
        exit(n);
    } else {
        close(pipe_in[READ]); // no need to read from input pipe here
        close(pipe_out[WRITE]); // no need to write to output pipe here

        while ((n = recv(source_sock, buffer, BUF_SIZE, 0)) > 0) { // read data from input socket
            if (write(pipe_in[WRITE], buffer, n) < 0) { // write data to input pipe of external command
                plog(LOG_ERR, "Cannot write to pipe: %m");
                exit(BROKEN_PIPE_ERROR);
            }
            if ((i = read(pipe_out[READ], buffer, BUF_SIZE)) > 0) { // read command output
                send(destination_sock, buffer, i, 0); // send data to output socket
            }
        }

        shutdown(destination_sock, SHUT_RDWR); // stop other processes from using socket
        close(destination_sock);

        shutdown(source_sock, SHUT_RDWR); // stop other processes from using socket
        close(source_sock);
    }
}

/* Create client connection */
int create_connection() {
    int sock = SERVER_SOCKET_ERROR;

    if ( mode == AX25 ) {
        struct addrinfo hints, *res=NULL;
        int validfamily=0;
        char portstr[12];

        memset(&hints, 0x00, sizeof(hints));

        hints.ai_flags    = AI_NUMERICSERV; /* numeric service number, not resolve */
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        sprintf(portstr, "%d", remote_port);

        /* check for numeric IP to specify IPv6 or IPv4 socket */
        if (validfamily = check_ipversion(remote_host)) {
             hints.ai_family = validfamily;
             hints.ai_flags |= AI_NUMERICHOST;  /* remote_host is a valid numeric ip, skip resolve */
        }

        /* Check if specified host is valid. Try to resolve address if remote_host is a hostname */
        if (getaddrinfo(remote_host,portstr , &hints, &res) != 0) {
            errno = EFAULT;
            return CLIENT_RESOLVE_ERROR;
        }

        if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
            return CLIENT_SOCKET_ERROR;
        }

        if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
            return CLIENT_CONNECT_ERROR;
        }

        if (res != NULL)
          freeaddrinfo(res);
    }

    if ( mode == TCP ) {
        struct sockaddr_ax25 local, remote;

        if (ax25_config_load_ports() == 0) {
            err(1, "Cannot load /etc/ax25/axports");
            return CLIENT_RESOLVE_ERROR;
        }

        char* port_call = (char*) ax25_config_get_addr(ax25_port);
        if ( port_call == NULL ) {
            err(1, "Cannot get local AX.25 address for %s port", ax25_port);
            return CLIENT_RESOLVE_ERROR;
        }

        if ((sock = socket(AF_AX25, SOCK_SEQPACKET, 0)) < 0) {
            return CLIENT_SOCKET_ERROR;
        }

        bzero((char *) &local, sizeof(struct sockaddr_ax25));
        local.sax25_family = AF_AX25;
        ax25_aton_entry(port_call, (char*)&local.sax25_call);
        local.sax25_ndigis = 0;

        if (bind(sock, (struct sockaddr *) &local, sizeof(local)) < 0) {
            return CLIENT_CONNECT_ERROR;
        }

        bzero((char *) &remote, sizeof(struct sockaddr_ax25));
        remote.sax25_family = AF_AX25;
        ax25_aton_entry(remote_host, (char*)&remote.sax25_call);
        remote.sax25_ndigis = 0;

        if (connect(sock, (struct sockaddr *)&remote, sizeof(struct sockaddr_ax25)) < 0) {
            close(sock);
            return CLIENT_CONNECT_ERROR;
        }
    }
    return sock;
}
/* vim: set et ts=4 sw=4: */
