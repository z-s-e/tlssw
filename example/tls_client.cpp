#include <tlssw/tlssw.h>

#include <arpa/inet.h>
#include <poll.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define HOST_PORT 12345

[[noreturn]] static void error(const char *msg)
{
    perror(msg);
    abort();
}

struct event_handler {
    tlssw::connection conn;
    char buffer[1024];
    bool shutdown = false;
    bool blocked = false;
    short events = 0;

    void operator()(tlssw::connection::MessageEvent e)
    {
        if( e.received > 0 ) {
            buffer[e.received] = 0;
            printf("Message received (%d bytes, sent: %d): %s\n", e.received, e.sent, buffer);
        } else {
            printf("No message received (sent: %d)\n", e.sent);
        }
    }

    void operator()(tlssw::connection::EndOfStreamEvent)
    {
        printf("EndOfStreamEvent\n");
        shutdown = true;
    }

    void operator()(tlssw::connection::ShutdownSentEvent)
    {
        printf("ShutdownSentEvent\n");
    }

    void operator()(tlssw::connection::BlockedEvent e)
    {
        printf("BlockedEvent\n");
        blocked = true;
        events = e.events;
    }

    void operator()(tlssw::connection::ErrorEvent)
    {
        fprintf(stderr, "ErrorEvent, aborting\n");
        abort();
    }

    void dispatch(bool block)
    {
        std::visit(*this, conn.next_event(buffer, sizeof(buffer), block ? tlssw::nanoseconds(-1)
                                                                        : tlssw::nanoseconds(0)));
    }
};

static int connect_socket()
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if( s < 0 )
        error("socket");

    struct sockaddr_in serv_addr = {};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_LOOPBACK;
    if( inet_aton("127.0.0.1", &serv_addr.sin_addr) != 1 )
        error("inet_aton");
    serv_addr.sin_port = htons(HOST_PORT);
    if( connect(s, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0 )
        error("connect");

    return s;
}


int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    int sockfd = connect_socket();

    printf("Connected\n");

    pollfd pfds[2];
    pfds[0].fd = 0;
    pfds[0].events = POLLIN;
    pfds[1].fd = sockfd;
    pfds[1].events = POLLIN;

    tlssw::configuration cfg;
    cfg.role = tlssw::Role::Client;
    cfg.method = tlssw::Method::PSKonly;
    cfg.psk_identity = "abc";
    cfg.psk = {0xa1, 0xb2, 0xc3, 0xd4};

    event_handler ev;
    if( auto r = ev.conn.reset(sockfd, cfg); r != tlssw::ResetResult::Ok ) {
        fprintf(stderr, "Reset error %d\n", int(r));
        abort();
    }

    while(true) {
        if( poll(pfds, 2, -1) == -1 )
            error("poll");

        if( pfds[0].revents ) {
            fgets(ev.buffer, sizeof(ev.buffer), stdin);
            auto s = strlen(ev.buffer);
            if( s <= 1 )
                break;

            if( ! ev.conn.schedule_send(ev.buffer, s - 1) )
                 fprintf(stderr, "Cannot schedule send...\n");
        }

        ev.blocked = false;
        while( ! ev.blocked )
            ev.dispatch(false);

        pfds[1].events = ev.events;
    }

    printf("Shutting down\n");

    ev.conn.schedule_shutdown();
    while( ! ev.shutdown )
        ev.dispatch(true);

    close(sockfd);
    return 0;
}
