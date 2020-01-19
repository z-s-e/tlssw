/* Copyright 2020 Zeno Sebastian Endemann <zeno.endemann@googlemail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef TLSSW_H
#define TLSSW_H

#include <chrono>
#include <filesystem>
#include <string>
#include <variant>
#include <vector>


namespace tlssw {


enum class Role {
    Invalid,
    Server,
    Client
};

enum class Method {
    Invalid,
    ServerAuthAnonymousClient,
    ServerAuthClientAuth,
    ServerAuthPSK,
    PSKonly
};

using filepath = std::filesystem::path;


struct configuration {
    Role role = Role::Invalid;
    Method method = Method::Invalid;

    filepath private_key_pem;
    filepath self_certificate_pem;
    filepath peer_certificate_pem;

    std::string psk_identity; // multiple psk identities not supported
    std::vector<unsigned char> psk;
};


enum class ResetResult {
    Ok,
    InvalidConfigRole,
    InvalidConfigMethod,
    InvalidConfigPrivateKey,
    InvalidConfigSelfCert,
    InvalidConfigPeerCert,
    InvalidConfigPSKIdentity,
    InvalidConfigPSK,
    UnexpectedInternalError
};

using nanoseconds = std::chrono::nanoseconds;


class connection {
public:
    connection();
    ~connection();
    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;
    connection(connection&& rhs);
    connection& operator=(connection&& rhs);

    // does NOT take ownership of socket
    ResetResult reset(int socket, const configuration& config);

    static unsigned maximum_buffer_size();

    // If this returns false, the call can be retried after a MessageEvent
    // occurs with schedulable >= size.
    bool schedule_send(const void* buffer, unsigned size);
    void schedule_shutdown();


    struct MessageEvent {
        unsigned received = 0;
        unsigned sent = 0;
        unsigned schedulable = 0;
    };
    struct EndOfStreamEvent {};
    struct ShutdownSentEvent {};
    struct BlockedEvent {
        short events = 0; // flag combination of POLLIN, POLLOUT
    };
    struct ErrorEvent {
        //TODO add members describing the error occured
        // -> https://www.openssl.org/docs/man1.1.1/man3/ERR_get_error.html
    };

    using Event = std::variant<MessageEvent,
                               EndOfStreamEvent,
                               ShutdownSentEvent,
                               BlockedEvent,
                               ErrorEvent>;

    // receive_buf may not be null, receive_buf_size must be > 0.
    // Specifying a negative value in timeout means an infinite timeout, like poll().
    Event next_event(void* receive_buf, unsigned receive_buf_size,
                     nanoseconds timeout = nanoseconds(0));

private:
    struct data;
    data* d = nullptr;
};

} // namespace tlssw

#endif // TLSSW_H
