## AA: Authoritative Answer
---
<br/>

This bit is valid in responses, and specifies that the responding name server 
is an authority for the domain name in question section.
Note that the contents of the answer section may have multiple owner names
because of aliases. The AA bit corresponds to the name which matches the 
query name, or the first owner name in the answer section.

<br/>

In query   | In response               
:-------|:---------------------
Ignored | Answer is from authoritative source.
