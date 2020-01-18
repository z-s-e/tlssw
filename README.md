# tlssw - TLS simplified wrapper lib

Prototype library for making it easy to secure a TCP connection with TLS.

Using OpenSSL API directly is rather complicated - this is an attempt to
create an API that is a lot harder to use incorrectly, as well as easier
to integrate into an event loop. Also, ease of use is preferred over
performance here. The library is intended to be used for applications
using only a single or few connections (e.g. peer2peer use cases), and
not for high connection count server applications. Finally, again for
simplicity's sake only the most basic TSL features are exposed.

Requirements: Linux, OpenSSL 1.1.1, cmake 3.10, C++17

Disclaimer: I am not a security expert, USE AT YOUR OWN RISK
