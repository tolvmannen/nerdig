## CD: Checking Disabled
---
<br/>

When processing a request with the CD bit set, a resolver will attempt 
to return all response data, even data that has failed DNSSEC validation.
If the DO bit is set in a query, it will be copied to the response.  

<br/>

Query   | Response               
:-------|:---------------------
Do not validate DNSSEC | Mirrored from Query
