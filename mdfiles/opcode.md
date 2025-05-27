## OPCODE
---
<br/>

A four bit field that specifies kind of query in this message. This value is set by the originator of a query and copied into the response.


Code    | Name                     
:-------|:---------------------
 0      | Standard query (QUERY)
 1      | Inverse query (Obsolete)
 2      | Sever status request (STATUS)
 3      | Unassigned
 4      | Notify
 5      | Update


For at full list of possible OPCODEs, se documentation at 
[IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5)
