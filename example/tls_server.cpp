/// Simple echo example server.

#include <tlssw/tlssw.h>

#include <arpa/inet.h>
#include <cassert>
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
    bool closeClient = false;

    void operator()(tlssw::connection::MessageEvent e)
    {
        if( e.received > 0 ) {
            buffer[e.received] = 0;
            printf("Message received (%d bytes, sent: %d): %s\n", e.received, e.sent, buffer);
            if( ! conn.schedule_send(buffer, e.received) )
                fprintf(stderr, "Cannot schedule send...\n");
        } else {
            printf("No message received (sent: %d)\n", e.sent);
        }
    }

    void operator()(tlssw::connection::EndOfStreamEvent)
    {
        printf("EndOfStreamEvent, scheduling shutdown\n");
        conn.schedule_shutdown();
    }

    void operator()(tlssw::connection::ShutdownSentEvent)
    {
        printf("ShutdownSentEvent\n");
        closeClient = true;
    }

    void operator()(tlssw::connection::BlockedEvent e)
    {
        assert(false);
    }

    void operator()(tlssw::connection::ErrorEvent e)
    {
        fprintf(stderr, "ErrorEvent\n");
        closeClient = true;
    }

    void dispatch()
    {
        std::visit(*this, conn.next_event(buffer, sizeof(buffer), tlssw::nanoseconds(-1)));
    }
};

static int listen_socket()
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if( s < 0 )
        error("socket");

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HOST_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int tmp = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp));

    if( bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0 )
        error("bind");

    if( listen(s, 1) < 0 )
        error("listen");

    return s;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    int sockfd = listen_socket();

    tlssw::configuration cfg;
    cfg.role = tlssw::Role::Server;
    cfg.method = tlssw::Method::PSKonly;
    cfg.psk_identity = "abc";
    cfg.psk = {0xa1, 0xb2, 0xc3, 0xd4};

    event_handler ev;

    while(true) {
        printf("Listening...\n");

        struct sockaddr_in clientname;
        socklen_t size = sizeof(clientname);
        int client = accept(sockfd, (struct sockaddr *) &clientname, &size);
        if( client < 0 )
            error("accept");

        printf("Client connected\n");

        if( auto r = ev.conn.reset(client, cfg); r != tlssw::ResetResult::Ok ) {
            fprintf(stderr, "Reset error %d\n", int(r));
            abort();
        }

        ev.closeClient = false;
        while( ! ev.closeClient )
            ev.dispatch();

        printf("Closing client\n");
        close(client);
    }

    return 1;
}
