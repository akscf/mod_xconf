<p>
  First of all, this module was written for provide the certain kind of conferences: when small number of the speakers are broadcasting to a very big number of listeners (it's common in education services) and the number of the latter may vary in a large ranges. This is a truncated version of one proprietary development, by mutual agreement with the customer, we decided to publish it under public domain license, maybe it will be interesting/useful for someone. <br>
  <br>
  Module can work in 2 modes: <br>
  <ul>
    <li>
    <strong>standalone</strong>   - a single instance (1-2 speakers and 1k-2k listeners)
    </li>
    <li>
    <strong>distributed</strong>  - this is a main mode (multiple Freeswitch instances maintenance a huge conference) <br>
		   for exchange media/events between nodes this module uses build-in service (and depends on your conditions it can be configured for: multicast or unicast mode) <br>
		   all the traffic between nodes can be encrypted and authenticated (use public networks without risky) <br>
		   unfortunately the module doesn't have built-in service to route subscribers between nodes and you should use some SBC for it<br>
    </li>
  </ul>
  <br>
  A few words about communication: <br>
  The media streams are sharing without any problems and this mechanism shows good work and short latency, what I can't say about events (there is a bit delay there). 
  So if you want to have more fast reaction on the events - the best way is rewrite this part and use some external service (such as rabbitmq or so on) <br>
</p>

### Featues
 - Playback function for members/conferences and MOH sound for alone member 
 - Possibility to give/take a voice to any member in any time (as well as: mute/unmute, deaf/undeaf, so on) 
 - Possibility to invite members to a conference (make an outgoing calls) (*) 
 - Protect a conference via password and authenticate admin by one 
 - Independent controls profiles for admin / users 
 - Lots of DTMF commands and easy way to extend them (see commands.c) 
 - VAD/AGC/CNG (maybe will appear echo suppression) 
 - One instance can to process: 2k-5k listeners and ~25 speakers (see: performance test)

### Related links
 - [Performance test](https://akscf.org/?page=projects/mod_xconf/perftest)

