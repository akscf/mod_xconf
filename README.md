<p>
 This is a high performance module for the Freeswitch to create audio conferences.<br>
This module provides services to create large capacity conferences for the scenario when you have several speakers (25-50 per instance) and extremely number of listeners.
</p>

# Basic featues
 - possible to work in two modes standalone and distributed
 - data exchange using multicast or point-to-point communication (with a helper module: mod_udptun)
 - encryption and authentication traffic between nodes (optional)
 - load reduction by reuse transcoding results
 - fast lockings and maximum paralleling
 - control by DTMF (separated profiles for admins and users) or console commands
 - protection throug PIN code  (conference, admin/user access)
 - vad, cng, agc and standard functions such as: playback/moh and so on (see commans.c)
 - simple balancer (todo)
 
# Performance tests
