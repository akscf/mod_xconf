<p>
 This is a well performance module for Freeswitch to create scalable conferences.<br>
 The module is perfect for the scenario of few speakers (up 25-50 per instance) and many listeners.<br>
 Distributed mode provides abillities to manage conferences capacity in real time.
</p>

# Basic featues
 - possible to work in two modes standalone and distributed
 - data exchange using multicast or point-to-point communication (with a helper module: mod_udptun)
 - encryption and authentication traffic between nodes (optional)
 - load reduction by truncate redundant transcoding (caching)
 - fast lockings and maximum paralleling
 - control by DTMF (separated profiles for admins and users) or console commands
 - protection throug PIN code  (conference, admin/user access)
 - vad, cng, agc and standard functions such as: playback/moh and so on (see commans.c)
 - simple balancer (todo)
 
# Performance tests
