# icn-llc (Link Layer Control for ICN)

A prototype shim for ICN, permitting forwarders and ICN end nodes 
to establish secure links among them.

## Architecture

    clients          cli                     cli
                      |                       |
    +-------+    +--------+              +--------+    +--------+
    |ccnx...| -- |LLC/DTLS| -- UDP/IP -- |DTLS/LLC| -- |ccnx ...|
    +-------+    +--------+              +--------+    +--------+

Clients connect to the LLC via UNIX named pipes.

The command line interface (cli) permits manual inspection and
configuration - it uses the same API as a local client would have or a
remote peer could invoke (modulo access control).

This prototype is for UDP only. However, the UDP/IP channel could be
replaced by raw IP, or Ethernet, in which case DTLS would be replaced
by IPsec or MACsec, respectively.
