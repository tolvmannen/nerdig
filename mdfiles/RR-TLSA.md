## TLSA (TLS Authentication Record)

Purpose: Specifies TLS server certificates and public keys, used in DANE (DNS-based Authentication of Named Entities) to secure TLS connections.
Example: _443._tcp.www.example.com. IN TLSA (
      0 0 1 d2abde240d7cd3ee6b4b28c54df034b9
            7983a1d16e8a410e4561cb106618e971 )

RFC: RFC 6698
