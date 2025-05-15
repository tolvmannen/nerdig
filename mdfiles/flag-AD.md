## AD: Authenticated Data

Query   | Response               
:-------|:---------------------
Validation requested  | Data validated
<br/>

In a Query, setting the AD bit is a signal indicating that the client 
understands and is interested in the value of the AD bit in the response.
This allows a client to indicate that it understands the AD bit without
also requesting DNSSEC data via the DO bit.
<br/>
In a Response, the AD bit indicates that the response is DNSSEC signed *and*
that the resolver has successfully validated the signatures. If a domain  
is signed, but the validating resolver is unable to verify the signatures, 
it will instead respond with status SERVFAIL and an empty answer section.  
