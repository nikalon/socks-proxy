#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define KB 1024
typedef uint8_t     u8;
typedef uint16_t    u16;

#define ARRAY_LEN(array) sizeof(array)/sizeof(array[0])

typedef struct {
    u8 *data;
    size_t length;
} Buffer;

Buffer net_buffer = {
    .data = (u8[8*KB]) {0},
    .length = 8*KB
};

bool take_bytes(Buffer *buffer, void *out, size_t num_bytes) {
    if (num_bytes > buffer->length) return false;

    memcpy(out, buffer->data, num_bytes);
    buffer->data += num_bytes;
    buffer->length -= num_bytes;
    return true;
}


typedef struct {
    char ip[INET6_ADDRSTRLEN]; // Should be enough space to store IPv4 and IPv6 addresses
    u16 port;
} NetHost;

typedef struct {
    int socket_fd;
    bool is_ipv4;
    NetHost my_host;
    NetHost their_host;
} TCPConnection;

bool tcp_read_data(TCPConnection *connection, Buffer *out) {
    // TODO: Use a ring buffer for reading data
    ssize_t read_bytes = recv(connection->socket_fd, net_buffer.data, net_buffer.length, 0);
    if (read_bytes <= 0) return false;

    out->data = net_buffer.data;
    out->length = read_bytes;
    return true;
}


typedef struct {
    u8 protocol_version;
    // We are only interested in the No Authentication field and ignore the rest
    bool supports_no_authentication;
} Handshake;

typedef struct {
    u8 protocol_version;
    u8 method;
} Response;

typedef enum {
    IPv4 = 0x01,
    DOMAIN_NAME = 0x03,
    IPv6 = 0x04
} AddressType;

typedef union {
    u8 ipv4[4];
    u8 ipv6[16];
    u8 domain_name[257]; // C string. Size is 2^8 + 1 for the null character.
} Address;

typedef struct {
    u8 protocol_version;
    u8 command;
    u8 unused;
    AddressType address_type;
    Address dst_address;
    u16 dst_port;
} SOCKS5_Request;

typedef struct {
    u8 protocol_version;
    u8 reply;
    u8 unused;
    AddressType address_type;
    Address bnd_address;
    u16 bnd_port;
} SOCKS5_Reply;


#define SOCKS_VERSION 0x5
#define NO_AUTHENTICATION_REQUIRED  0x00
#define NO_ACCEPTABLE_METHODS       0xFF
#define PORT "1080" // As string because getaddrinfo() needs it that way

NetHost get_host(int address_family, struct sockaddr *addr) {
    NetHost out = {0};

    void *src = NULL;
    if (address_family == AF_INET) {
        // IPv4
        struct sockaddr_in *addr_ipv4 = (struct sockaddr_in *) addr;
        src = &addr_ipv4->sin_addr;
        out.port = ntohs(addr_ipv4->sin_port);
    } else if (address_family == AF_INET6) {
        // IPv6
        struct sockaddr_in6 *addr_ipv6 = (struct sockaddr_in6 *) addr;
        src = &addr_ipv6->sin6_addr;
        out.port = ntohs(addr_ipv6->sin6_port);
    }
    inet_ntop(address_family, src, out.ip, ARRAY_LEN(out.ip));

    return out;
}

void close_connection(TCPConnection *connection) {
    assert(connection != NULL);
    printf("[INFO] [%s]:%u closed connection\n", connection->their_host.ip, connection->their_host.port);
    close(connection->socket_fd);
    memset(connection, 0, sizeof(*connection));
    connection->socket_fd = -1;
}

bool read_handshake(TCPConnection *connection, Handshake *out) {
    memset(out, 0, sizeof(*out));

    Buffer buffer = {0};
    if (! tcp_read_data(connection, &buffer)) return false;
    if (buffer.length < 2) {
        return false;
    }

    u8 protocol_version ;
    u8 num_methods;
    if (!take_bytes(&buffer, &protocol_version, sizeof(protocol_version))) return false;
    if (!take_bytes(&buffer, &num_methods, sizeof(protocol_version))) return false;
    if (num_methods == 0) return false;

    bool noauth = false;
    for (int i = 0; i < num_methods; i++) {
        u8 method;
        if (!take_bytes(&buffer, &method, sizeof(method))) return false;
        if (method == NO_AUTHENTICATION_REQUIRED) {
            // No authentication required. We only care about this method and ignore the rest.
            noauth = true;
            break;
        }
    }

    out->protocol_version = protocol_version;
    out->supports_no_authentication = noauth;
    return true;
}

void send_response(Response response, u8 *buffer) {
    // TODO: We should write into a ring buffer, and then flush
    // We don't perform any validation when writing to the buffer. It is expected for the caller to pass a buffer big
    // enough to write data.
    *buffer++ = response.protocol_version;
    *buffer++ = response.method;
}

bool read_request(TCPConnection *connection, SOCKS5_Request *out) {
    memset(out, 0, sizeof(*out));

    Buffer buffer = {0};
    if (! tcp_read_data(connection, &buffer)) return false;

    u8 version, command, unused, address_type;
    if (!take_bytes(&buffer, &version, sizeof(version))) return false;
    if (!take_bytes(&buffer, &command, sizeof(command))) return false;
    if (!take_bytes(&buffer, &unused, sizeof(unused))) return false;
    if (!take_bytes(&buffer, &address_type, sizeof(address_type))) return false;

    if (address_type == 0x01) {
        // IPv4 address
        u8 ipv4[4] = {0};
        if (!take_bytes(&buffer, &ipv4, sizeof(ipv4))) return false;

        // Parse successful. Write output data.
        memcpy(out->dst_address.ipv4, ipv4, sizeof(ipv4));
    } else if (address_type == 0x03) {
        // Domain name. The read string doesn't contain a null character. We add it manually.
        u8 strlen;
        u8 domain_name[257] = {0};
        if (!take_bytes(&buffer, &strlen, sizeof(strlen))) return false;
        if (!take_bytes(&buffer, &domain_name, strlen)) return false;

        domain_name[strlen] = '\0';
        memcpy(out->dst_address.domain_name, domain_name, strlen + 1);
    } else if (address_type == 0x04) {
        // IPv6 address
        u8 ipv6[16] = {0};
        if (!take_bytes(&buffer, &ipv6, sizeof(ipv6))) return false;

        // Parse successful. Write output data.
        memcpy(out->dst_address.ipv6, ipv6, sizeof(ipv6));
    } else {
        return false;
    }

    u16 port;
    if (!take_bytes(&buffer, &port, sizeof(port))) return false;
    port = ntohs(port);

    out->protocol_version = version;
    out->command = command;
    out->unused = unused;
    out->address_type = address_type;
    out->dst_port = port;
    return true;
}

size_t send_reply(SOCKS5_Reply reply, u8 *buffer) {
    // We don't perform any validation when writing to the buffer. It is expected for the caller to pass a buffer big
    // enough to write data.
    u8 *start = buffer;

    *buffer++ = reply.protocol_version;
    *buffer++ = reply.reply;
    *buffer++ = reply.unused;
    *buffer++ = reply.address_type;
    switch (reply.address_type) {
        case IPv4: {
            for (int i = 0; i < 4; i++) *buffer++ = reply.bnd_address.ipv4[i];
            break;
        }

        case DOMAIN_NAME: {
            size_t len = strlen((char *) reply.bnd_address.domain_name); 
            *buffer++ = len;
            for (size_t i = 0; i < len; i++) *buffer++ = reply.bnd_address.domain_name[i];
            break;
        }

        case IPv6: {
            for (int i = 0; i < 16; i++) *buffer++ = reply.bnd_address.ipv6[i];
            break;
        }
    }

    u16 n_port = htons(reply.bnd_port);
    size_t len = sizeof(n_port);
    memcpy(buffer, &n_port, len);
    buffer += len;
    return buffer - start;
}

void get_human_readable_IP(AddressType address_type, Address address, char *out, size_t strlen) {
    int af = -1;
    void *src = NULL;
    switch (address_type) {
        case IPv4: {
            // IPv4
            af = AF_INET;
            src = address.ipv4;
            break;
        }

        case IPv6: {
            // IPv6
            af = AF_INET6;
            src = address.ipv6;
            break;
        }

        default: {
            break;
        }
    }

    inet_ntop(af, src, out, strlen);
}

TCPConnection connect_to_remote_server(AddressType address_type, Address server_address, u16 port) {
    TCPConnection out = {0};
    out.socket_fd = -1;

    // Convert IP to a string, because it is required by getaddrinfo()
    char hostname[257] = {0}; // Should be enough space for IPv4, IPv6 and domain names
    get_human_readable_IP(address_type, server_address, hostname, ARRAY_LEN(hostname));

    // Convert port to string, because it is required by getaddrinfo()
    char port_str[6] = ""; // Maximum port is 65535, which is 5 digits + 1 for the end null character
    snprintf(port_str, ARRAY_LEN(port_str), "%u", port);

    // Listen any address in IPv4 or IPv6. It will select either IP version automatically.
    struct addrinfo hint = {0};
    hint.ai_socktype = SOCK_STREAM; // TCP

    switch (address_type) {
        case IPv4: {
            hint.ai_family = AF_INET;
            break;
        }

        case DOMAIN_NAME: {
            size_t domain_len = strlen((char *) server_address.domain_name);
            memcpy(hostname, server_address.domain_name, domain_len);
            break;
        }

        case IPv6: {
            hint.ai_family = AF_INET6;
            break;
        }

        default: {
            return out;
        }
    }

    struct addrinfo *my_addr_info = NULL;
    if (getaddrinfo(hostname, port_str, &hint, &my_addr_info) != 0) return out;

    // TODO: We should choose an alternative address in case of failure in socket()
    int server_fd = socket(my_addr_info->ai_family, my_addr_info->ai_socktype, my_addr_info->ai_protocol);

    // Establish a connection
    if (connect(server_fd, my_addr_info->ai_addr, my_addr_info->ai_addrlen) != 0) {
        printf("[INFO] Cannot establish a connection to %.*s\n", (int) strlen(hostname), hostname);
        close(server_fd);
        server_fd = -1;
    }

    struct sockaddr their_addr = {0};
    socklen_t their_addr_len = (socklen_t) sizeof(their_addr);
    int ret = getpeername(server_fd, &their_addr, &their_addr_len);
    assert(ret == 0 && "getpeername() didn't receive valid arguments");

    // Connection established
    out.socket_fd = server_fd;
    out.is_ipv4 = my_addr_info->ai_family == AF_INET;
    out.my_host = get_host(my_addr_info->ai_family, my_addr_info->ai_addr);
    out.their_host = get_host(my_addr_info->ai_family, &their_addr);
    return out;
}

void bridge_connection_between_hosts(TCPConnection *client_connection, TCPConnection *remote_connection) {
    struct pollfd fds[2];

    // Host A
    fds[0].fd = client_connection->socket_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    // Host B
    fds[1].fd = remote_connection->socket_fd;
    fds[1].events = POLLIN;
    fds[1].revents = 0;

    printf("[INFO] Bridge connection between [%s]:%u and [%s]:%u\n",
           client_connection->their_host.ip, client_connection->their_host.port,
           remote_connection->their_host.ip, remote_connection->their_host.port);
    bool should_close = false;
    while (!should_close) {
        if (poll(fds, ARRAY_LEN(fds), -1) <= 0) {
            printf("[ERROR] poll() had an error\n");
            break;
        }

        for (size_t i = 0; i < ARRAY_LEN(fds); i++) {
            if (fds[i].revents & POLLIN) {
                // Read data and sent to other host
                ssize_t read_bytes = recv(fds[i].fd, net_buffer.data, net_buffer.length, 0);
                if (read_bytes <= 0) {
                    // Host closed connection
                    should_close = true;
                } else {
                    // Forward data to the other host in a blocking way
                    send(fds[(i + 1) % 2].fd, net_buffer.data, read_bytes, 0);
                }
            }
        }
    }
}

void handle_client(TCPConnection *client_connection) {
    // TODO: Send error to client when parsing fails
    printf("[INFO] Connection from host [%s]:%u\n", client_connection->their_host.ip, client_connection->their_host.port);


    // Read and validate hanshake
    Handshake handshake = {0};
    if (!read_handshake(client_connection, &handshake)) {
        printf("[ERROR] Invalid handshake\n");
        return;
    }

    if (handshake.protocol_version != SOCKS_VERSION) {
        printf("[ERROR] Invalid SOCKS version in handshake\n");
        return;
    }

    if (!handshake.supports_no_authentication) {
        printf("[ERROR] Client doesn't support No Authentication method\n");
        return;
    }


    // Send response
    Response resp = {
        .protocol_version = SOCKS_VERSION,
        .method = NO_AUTHENTICATION_REQUIRED
    };
    u8 resp_buffer[2] = {0};
    send_response(resp, resp_buffer);
    if (send(client_connection->socket_fd, resp_buffer, ARRAY_LEN(resp_buffer), 0) <= 0) {
        printf("[ERROR] Could not send response to client\n");
        return;
    }


    // Read and validate request
    SOCKS5_Request request = {0};
    if (!read_request(client_connection, &request)) {
        printf("[ERROR] Invalid client request\n");
        return;
    }

    if (request.protocol_version != SOCKS_VERSION) {
        printf("[ERROR] Client sent requets with invalid SOCKS version\n");
        return;
    }


    TCPConnection server_connection = connect_to_remote_server(request.address_type, request.dst_address, request.dst_port);


    // Send reply
    // TODO: Send error to client if we cannot connect to the remote server
    SOCKS5_Reply reply = {0};
    reply.protocol_version = SOCKS_VERSION;
    reply.address_type = request.address_type;
    if (server_connection.is_ipv4) {
        reply.address_type = IPv4;
        inet_pton(AF_INET, server_connection.my_host.ip, &reply.bnd_address.ipv4);
    } else {
        reply.address_type = IPv6;
        inet_pton(AF_INET6, server_connection.my_host.ip, &reply.bnd_address.ipv6);
    }
    reply.bnd_port = server_connection.my_host.port;
    if (request.command == 0x01) {
        // Connect
        reply.reply = 0x00; // Succeeded
    } else {
        // TODO: Support more commands
        printf("[ERROR] Client sent unsupported command: %d\n", request.command);
        reply.reply = 0x05; // Connection refused
    }

    u8 reply_buffer[1024] = {0};
    size_t len = send_reply(reply, reply_buffer);
    if (!send(client_connection->socket_fd, reply_buffer, len, 0)) {
        printf("[ERROR] I/O error\n");
        return;
    }

    bridge_connection_between_hosts(client_connection, &server_connection);
    close_connection(client_connection);
    close_connection(&server_connection);
}

void handle_sigchld() {
    // Reap zombie processes. We don't care about children's exit status code.
    int prev_errno = errno;

    pid_t any_child = -1;
    while (waitpid(any_child, NULL, WNOHANG) > 0);

    // Restore original errno. We do this because waitpid() overwrites errno when using the option WNOHANG.
    errno = prev_errno;
}

int main(int argc, char **argv) {
    printf("[INFO] Starting SOCKS server\n");

    signal(SIGCHLD, handle_sigchld);

    struct addrinfo *my_addr;
    struct addrinfo hint = {0};
    hint.ai_flags = AI_PASSIVE;     // Wildcard IP address. getaddrinfo's first argument must be NULL
    hint.ai_family = AF_UNSPEC;     // Allow IPv4 or IPv6
    hint.ai_socktype = SOCK_STREAM; // TCP

    int res;
    if ((res = getaddrinfo(NULL, PORT, &hint, &my_addr)) != 0) {
        printf("[ERROR] %s\n", gai_strerror(res));
        return 1;
    }

    // TODO: We should choose an alternative address in case of failure in socket()
    // Choose any IP address and use it to listen for incoming connections
    int socket_fd = socket(my_addr->ai_family, my_addr->ai_socktype, my_addr->ai_protocol);
    if (socket_fd < 0) {
        printf("[ERROR] Could not create a TCP socket\n");
        return 1;
    }

    if (bind(socket_fd, my_addr->ai_addr, my_addr->ai_addrlen) < 0) {
        printf("[ERROR] Could not bind a TCP socket into an IP address and port\n");
        return 1;
    }

    if (listen(socket_fd, SOMAXCONN) < 0) {
        printf("[ERROR] Could not start server\n");
        return 1;
    }

    NetHost my_host = get_host(my_addr->ai_family, my_addr->ai_addr);
    printf("[INFO] Server started at %s port %u\n", my_host.ip, my_host.port);

    int client_fd;
    struct sockaddr client_addr = {0};
    socklen_t client_addr_len = sizeof(client_addr);
    while ((client_fd = accept(socket_fd, &client_addr, &client_addr_len)) >= 0) {
        pid_t fpid = fork();
        if (fpid < 0) {
            printf("[ERROR] Cannot handle incoming connection with fork()\n");
        } else if (fpid == 0) {
            // Child process
            TCPConnection connection = {
                .socket_fd = client_fd,
                .is_ipv4 = my_addr->ai_family == AF_INET,
                .my_host = my_host,
                .their_host = get_host(my_addr->ai_family, &client_addr)
            };
            handle_client(&connection);
            exit(0);
        }

        close(client_fd);
    }

    close(socket_fd);
    printf("[INFO] Server stopped\n");

    return 0;
}
