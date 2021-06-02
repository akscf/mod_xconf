<p>
 This module provides services to create large capacity conferences for the scenario there are several speakers (25-50 per instance) and extremely number of listeners. Distributed mode helps to separate load between all the nodes, boost summary capacity and provide good quality for audio/video.<br>
 Version 1.7.x - supports only audio conferences.
</p>

# Basic featues
 - possible to work in two modes standalone and distributed
 - data exchange using multicast or unicast communication (with a helper module: mod_udptun)
 - encryption and authentication traffic between nodes (optional)
 - load reduction by reuse transcoding results
 - fast lockings and maximum paralleling
 - speakers limit: 25-50 per instance
 - listeners limit: 2000-5000 per instance (low/middle cost vm) / summary upper limit is: 100k-200k (*)
 
# ToDo
- close parts with 'todo' label

# Performance tests
```
** Test #1 (optimal vm) **
CPU.............: Intel Core Processor (Haswell, no TSX) [8 cores / 2992.968Mhz / 16384KB cache / 5985.93 bogomips]
MemTotal........: 30152704 kB
Listeners codec.: G711
Transcoding.....: enabled
mod_xconf.......: 1.7 (freeswitch 1.8.7 x64)
Speakers........: 1
Total session...: 5000++
Test lasted.....: 30-60 min

freeswitch@conference-1> status
UP 0 years, 0 days, 2 hours, 9 minutes, 54 seconds, 455 milliseconds, 408 microseconds
FreeSWITCH (Version 1.8.7 64bit) is ready
11773 session(s) since startup
4759 session(s) - peak 5159, last 5min 4759
72 session(s) per Sec out of max 1000, peak 107, last 5min 97
10000 session(s) max
min idle cpu 0.00/3.07
Current Stack Size/Max 240K/8192K

In my opinion, we could get 1-2k sessions more without problems.


** Test #2 (lowcost vm, truncated cpu and memory) **
CPU.............: Intel Core Processor (Haswell, no TSX) [4 cores / 2992.968Mhz / 16384KB cache / 5985.93 bogomips]
MemTotal........: 15033144 kB
Listeners codec.: G711
Transcoding.....: enabled
mod_xconf.......: 1.7 (freeswitch 1.8.7 x64)
Speakers........: 1
Total session...: 3001 (optimal 2500)
Test lasted.....: 20-30 min

reeswitch@conference-1> status
UP 0 years, 0 days, 0 hours, 21 minutes, 24 seconds, 525 milliseconds, 291 microseconds
FreeSWITCH (Version 1.8.7 64bit) is ready
3013 session(s) since startup
3001 session(s) - peak 3001, last 5min 3001
77 session(s) per Sec out of max 1000, peak 107, last 5min 107
10000 session(s) max
min idle cpu 0.00/38.40
Current Stack Size/Max 240K/8192K

We managed to get 3k sessions but audio was unstable and summary load on the system was quite high.
The optimal sessions number for this sort of vm is 2500 (2300) no more.
```
