/* Copyright 2020 Zeno Sebastian Endemann <zeno.endemann@googlemail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <tlssw/tlssw.h>

#include <openssl/ssl.h>
//#include <openssl/err.h>

#include <poll.h>
#include <string.h>


namespace tlssw {

struct connection::data {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;

    std::string psk_identity;
    std::vector<unsigned char> psk;

    unsigned char* writeBuffer = nullptr;
    unsigned pendingWrite = 0;

    int fd = -1;
    bool eos = false;
    bool shutdownPending = false;
    bool shutdown = false;

    ~data()
    {
        cleanup_all();
    }

    void cleanup() {
        if( ssl ) {
            SSL_free(ssl);
            ssl = nullptr;
        }
        if( ctx ) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
        psk_identity.clear();
        psk.clear();
    }

    void cleanup_all() {
        cleanup();
        if( writeBuffer ) {
            delete [] writeBuffer;
            writeBuffer = nullptr;
        }
    }
};

connection::connection()
    : d(new data)
{
}

connection::~connection()
{
    delete d;
}

connection::connection(connection&& rhs)
    : d(new data)
{
    std::swap(d, rhs.d);
}

connection &connection::operator=(connection&& rhs)
{
    d->cleanup_all();
    std::swap(d, rhs.d);
    return *this;
}

static unsigned int psk_copy_key(SSL* ssl, unsigned char* psk, unsigned int max_psk_len)
{
    auto key = reinterpret_cast<std::vector<unsigned char>*>(SSL_get_ex_data(ssl, 1));
    if( key->size() > max_psk_len )
        return 0;
    memcpy(psk, key->data(), key->size());
    return key->size();
}

static unsigned int psk_server_cb(SSL* ssl, const char* identity,
                                  unsigned char* psk,
                                  unsigned int max_psk_len)
{
    auto id = reinterpret_cast<std::string*>(SSL_get_ex_data(ssl, 0));
    if( strcmp(identity, id->data()) != 0 )
        return 0;
    return psk_copy_key(ssl, psk, max_psk_len);
}

static unsigned int psk_client_cb(SSL* ssl, const char* /*hint*/,
                                  char* identity, unsigned int max_identity_len,
                                  unsigned char* psk, unsigned int max_psk_len)
{
    auto id = reinterpret_cast<std::string*>(SSL_get_ex_data(ssl, 0));
    if( id->size() + 1 > max_identity_len )
        return 0;
    strcpy(identity, id->data());
    return psk_copy_key(ssl, psk, max_psk_len);
}

ResetResult connection::reset(int socket, const configuration &config)
{
    d->cleanup();

    if( config.role == Role::Invalid )
        return ResetResult::InvalidConfigRole;
    if( config.method == Method::Invalid )
        return ResetResult::InvalidConfigMethod;

    switch( config.method ) {
    case Method::ServerAuthPSK:
    case Method::PSKonly:
        if( config.psk_identity.empty() )
            return ResetResult::InvalidConfigPSKIdentity;
        if( config.psk.empty() )
            return ResetResult::InvalidConfigPSK;
        d->psk_identity = config.psk_identity;
        d->psk = config.psk;
        break;
    default:
        ;
    }

    d->pendingWrite = 0;
    d->eos = false;
    d->shutdownPending = false;
    d->shutdown = false;

    d->fd = socket;
    if( ! BIO_socket_nbio(socket, 1) )
        return ResetResult::UnexpectedInternalError;

    { // setup openssl context and ssl
        SSL_CTX* ctx = SSL_CTX_new(config.role == Role::Client ? TLS_client_method()
                                                               : TLS_server_method());
        if( ! ctx )
            return ResetResult::UnexpectedInternalError;

        struct ctx_cleanup {
            SSL_CTX* ref = nullptr;
            ~ctx_cleanup() { if( ref ) SSL_CTX_free(ref); }
        } cleanup = {ctx};

        if( (config.role == Role::Server && config.method != Method::PSKonly)
            || (config.role == Role::Client && config.method == Method::ServerAuthClientAuth)
          ) {
            if( SSL_CTX_use_certificate_chain_file(ctx, config.self_certificate_pem.c_str()) <= 0 )
                return ResetResult::InvalidConfigSelfCert;

            if( SSL_CTX_use_PrivateKey_file(ctx, config.private_key_pem.c_str(), SSL_FILETYPE_PEM) <= 0 )
                return ResetResult::InvalidConfigPrivateKey;

            if( SSL_CTX_check_private_key(ctx) != 1 )
                return ResetResult::InvalidConfigPrivateKey;
        }

        if( config.role == Role::Server && config.method == Method::ServerAuthClientAuth ) {
            SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(config.peer_certificate_pem.c_str()));
            if( SSL_CTX_load_verify_locations(ctx, config.peer_certificate_pem.c_str(), nullptr) != 1 )
                return ResetResult::InvalidConfigPeerCert;
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, nullptr);
            SSL_CTX_set_verify_depth(ctx, 0);
        } else if( config.role == Role::Client && config.method != Method::PSKonly) {
            if( SSL_CTX_load_verify_locations(ctx, config.peer_certificate_pem.c_str(), nullptr) != 1 )
                return ResetResult::InvalidConfigPeerCert;

            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        }

        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

        auto ssl = SSL_new(ctx);
        if( ssl == nullptr )
            return ResetResult::UnexpectedInternalError;
        SSL_set_fd(ssl, socket);
        if( config.role == Role::Client )
            SSL_set_connect_state(ssl);
        else
            SSL_set_accept_state(ssl);

        if( config.method == Method::ServerAuthPSK || config.method == Method::PSKonly ) {
            if( config.role == Role::Client ) {
                SSL_set_psk_client_callback(ssl, psk_client_cb);
            } else {
                SSL_set_psk_server_callback(ssl, psk_server_cb);
            }
            if( SSL_set_ex_data(ssl, 0, &(d->psk_identity)) != 1 ) {
                SSL_free(ssl);
                return ResetResult::UnexpectedInternalError;
            }
            if( SSL_set_ex_data(ssl, 1, &(d->psk)) != 1 ) {
                SSL_free(ssl);
                return ResetResult::UnexpectedInternalError;
            }
        }

        cleanup.ref = nullptr;
        d->ctx = ctx;
        d->ssl = ssl;
    }

    if( d->writeBuffer == nullptr )
        d->writeBuffer = new unsigned char[maximum_buffer_size()];

    return ResetResult::Ok;
}

unsigned connection::maximum_buffer_size()
{
    return SSL3_RT_MAX_PLAIN_LENGTH;
}

bool connection::schedule_send(const void *buffer, unsigned size)
{
    if( d->pendingWrite > 0
            || size > maximum_buffer_size()
            || d->shutdownPending
            || d->shutdown
            || d->ssl == nullptr )
        return false;

    memcpy(d->writeBuffer, buffer, size);
    d->pendingWrite = size;
    return true;
}

void connection::schedule_shutdown()
{
    if( ! d->shutdown )
        d->shutdownPending = true;
}

connection::Event connection::next_event(void *receive_buf, unsigned receive_buf_size,
                                         nanoseconds timeout)
{
    if( d->ssl == nullptr || receive_buf_size == 0 )
        return ErrorEvent();

    const auto t = (timeout > nanoseconds(0) ? std::chrono::steady_clock::now()
                                             : std::chrono::steady_clock::time_point());

retry:
    bool wantRead = false;
    bool wantWrite = false;
    MessageEvent msg;

    if( d->shutdownPending && d->pendingWrite == 0 && SSL_is_init_finished(d->ssl) ) {
        int s = SSL_shutdown(d->ssl);
        if( s >= 0 ) {
            d->shutdownPending = false;
            d->shutdown = true;
            return ShutdownSentEvent();
        } else {
            switch( SSL_get_error(d->ssl, s) ) {
            case SSL_ERROR_WANT_READ:
                wantRead = true;
                break;
            case SSL_ERROR_WANT_WRITE:
                wantWrite = true;
                break;
            default:
                return ErrorEvent();
            }
        }
    }

    if( ! d->eos ) {
        int r = SSL_read(d->ssl, receive_buf, int(receive_buf_size));
        if( r > 0 ) {
            msg.received = unsigned(r);
        } else {
            switch( SSL_get_error(d->ssl, r) ) {
            case SSL_ERROR_ZERO_RETURN:
                d->eos = true;
                return EndOfStreamEvent();
            case SSL_ERROR_WANT_READ:
                wantRead = true;
                break;
            case SSL_ERROR_WANT_WRITE:
                wantWrite = true;
                break;
            default:
                return ErrorEvent();
            }
        }
    }

    if( d->pendingWrite > 0 ) {
        int w = SSL_write(d->ssl, d->writeBuffer, int(d->pendingWrite));

        if( w > 0 ) {
            //assert(w == d->pendingWrite);
            d->pendingWrite = 0;
            msg.sent = unsigned(w);
            msg.schedulable = d->shutdownPending ? 0 : maximum_buffer_size();
            return msg;
        }

        switch( SSL_get_error(d->ssl, w) ) {
        case SSL_ERROR_WANT_READ:
            wantRead = true;
            break;
        case SSL_ERROR_WANT_WRITE:
            wantWrite = true;
            break;
        default:
            if( msg.received == 0 ) // TODO alternatives?
                return ErrorEvent();
        }
    } else {
        msg.schedulable = (d->shutdownPending || d->shutdown) ? 0 : maximum_buffer_size();
    }

    if( msg.received > 0 )
        return msg;

    const short events = (wantRead ? POLLIN : 0) | (wantWrite ? POLLOUT : 0);

    if( events == 0 )
        return ErrorEvent();

    if( timeout != nanoseconds(0) ) {
        struct timespec ts;
        if( timeout > nanoseconds(0) ) {
            auto d = std::chrono::steady_clock::now() - t;
            if( d >= timeout )
                return BlockedEvent { events };
            ts.tv_nsec = d.count() % std::nano::den;
            ts.tv_sec = d.count() / std::nano::den;
        }

        pollfd pfd = {};
        pfd.fd = d->fd;
        pfd.events = events;
        switch( ppoll(&pfd, 1, timeout < nanoseconds(0) ? nullptr : &ts, nullptr) ) {
        case -1:
            return ErrorEvent();
        case 0:
            break;
        default:
            goto retry;
        }
    }

    return BlockedEvent { events };
}


} // namespace tlssw
