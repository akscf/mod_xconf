<p>
  This module was written to provide the certain kind of conferences: where small number of speakers are broadcasting to a very big number of listeners and number of latest may vary in a large ranges. <br>
  <br>
  The module can operate in two modes: <br>
  <ul>
    <li>
    <strong>standalone</strong>   - a single instance (~25 speakers and 1k-2k listeners) 
    </li>
    <li>
    <strong>distributed</strong>  - where multiple Freeswitch instances maintenance a huge conference(s) <br>
    to share media/events between nodes it uses built-in service based on UDP (multicast/unicast) <br>
    the traffic can be encrypted and authenticated that allows to live without VPN and use public networks <br>
    unfortunately the module can not route subscribers and balance the load so you should use some SBC for solve it <br>
    every instance able to process about 2k-5k listeners and about 25 spreakes [Performance test](http://akscf.org/?page=projects/mod_xconf/perftest) <br>
    </li>
  </ul>
  <br>
   A few words about communication: <br>
   The media streams are sharing without any problems and this mechanism shows low latency and quite well, what I can't say about events (there is a little problems there), <br>
   therefore if you want to have faster reaction on the events - rewrite this part and use some external tools such as rabbitmq or so on. <br>
</p>

### Featues
 - Playback function for members/conferences and MOH sound for alone member 
 - Possible to give/take a voice to any member in any time (as well as: mute/unmute, deaf/undeaf, so on) 
 - Possible to invite members to a conference (make an outgoing calls) (*) 
 - Password protection for conference / admin access 
 - Independent controls profiles for admin / users 
 - Lots of DTMF commands and easy way to extend them (see commands.c) 
 - VAD/AGC/CNG (maybe will appear echo suppression) 

### Related links
 - [Performance test](http://akscf.org/?page=projects/mod_xconf/perftest)

