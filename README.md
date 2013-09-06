geoipdns
========
Location-Aware Authoritative DNS Server

http://geoipdns.org by Adrian Ilarion Ciobanu is a fork of the djbdns package which functions 
as a drop-in replacement for tinydns enhancing it's location-awareness and speed. Location aware 
DNS can be used to optimize a CDN, find the "most local" peer in a VoIP service, serve regionally 
specific content or even remove services completely for a particular region.

IP location information can be imported from freely available data sources such as MaxMind's 
GeoLite City ( http://dev.maxmind.com/geoip/legacy/geolite/ ) with a high degree of detail and 
used to tailor DNS responses based upon the requestor's location. By moving location awareness 
into DNS, users can be sent directly to their most local server without the need for application 
modification.

Although data from a standard tinydns data file can be directly used by geoipdns, location (%) 
records and names using them are described with a new syntax. (detailed in the example below) 
Once compiled, geoipdns uses a superfast hash in memory to respond to queries quickly because IP 
block maps can become very large. It isn't uncommon for a city-level IP block map of the world 
(such as the one from MaxMind) to be over 5 million rows. Although this map is kept in memory, 
geoipdns will still reload the map when data.cdb changes on disk.

If you are more comfortable with BIND, there is a similar GeoDNS BIND patch also available.

Example Implementation
======================

Here is a complete data file for a geoipdns server running on 1.2.3.4:

    .example.com:1.2.3.4:a
    
    %boston:71.233.148.0:24
    %boston:71.232.0.0:16
    %new-york:71.250.0.0:16
    %new-york:71.251.10.0:24
    
    +www.example.com:11.11.11.11:1200::boston
    +www.example.com:22.22.22.22:1200::new-york
    +www.example.com:99.99.99.99:1200::nomatch

Clients requesting 'www.example.com' from within one of the 'boston' blocks (71.233.148.0/24 
or 71.232.0.0/16) will get the answer '11.11.11.11' while clients requesting the same name 
from any of the blocks labeled 'new-york' (71.250.0.0/16 or 71.251.10.0/24) will get 
'22.22.22.22'. Clients from outside any of the listed blocks are returned the nomatch target 
'99.99.99.99'.

The format for LOC (location) records is:

    %target:ipnet:bitnetmask:mapname:username

although mapname and username are optional. All the traditional record types now accept a target 
(making the record LOC-enabled) and optional mapname and username parameters. For example:

    =fqdn:ip:ttl:timestamp:target:mapname:username
    +fqdn:ip:ttl:timestamp:target:mapname:username
    @fqdn:ip:x:dist:ttl:timestamp:target:mapname:username
    Cfqdn:p:ttl:timestamp:target:mapname:username
    'fqdn:s:ttl:timestamp:target:mapname:username
    ^fqdn:p:ttl:timestamp:target:mapname:username

All the standard tinydns records will also work but only names with targets defined will cause a 
location sensitive lookup. Therefore you can use an already existing tinydns data file and add 
location-aware names only where needed. geoipdns skips looking up the requestor's block if there 
isn't a LOC target defined amongst the answers.

Credits
=======

geoipdns was written by Adrian Ilarion Ciobanu and is a patched and renamed version of tinydns from 
the djbdns package by Daniel J. Bernstein.
