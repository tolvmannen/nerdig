## DO: DNSSEC Ok

Query   | Response               
:-------|:---------------------
Include DNSSEC RRs  | Mirrored from query
<br/>

Setting the DO bit to 1 in a query indicates to the server that the client 
is able to accept DNSSEC security RRs. A DNSSEC-aware nameserver will then
also set this bit in the resopnse.   
