# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An L2 learning switch.

It is derived from one written live for an SDN crash course.
It is somwhat similar to NOX's pyswitch in that it installs
exact-match rules for each flow.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
from pox.lib.packet.arp import arp
import time
import yaml

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

class LearningSwitch (object):
  """
  The learning switch "brain" associated with a single OpenFlow switch.

  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.

  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  that port.

  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).

  In short, our algorithm looks like this:

  For each packet from the switch:
  1) Use source address and switch port to update address/port table
  2) Is transparent = False and either Ethertype is LLDP or the packet's
     destination address is a Bridge Filtered address?
     Yes:
        2a) Drop packet -- don't forward link-local traffic (LLDP, 802.1x)
            DONE
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
            DONE
  4) Port for destination address in our address/port table?
     No:
        4a) Flood the packet
            DONE
  5) Is output port the same as input port?
     Yes:
        5a) Drop packet and similar ones for a while
  6) Install flow table entry in the switch so that this
     flow goes out the appopriate port
     6a) Send the packet out appropriate port
  """
  def __init__ (self, connection, transparent, local_ips, links, ip_to_city_idx):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    self.local_ips = local_ips
    self.links = links
    self.ip_to_city_idx = ip_to_city_idx
    print ("Setting local_ips = ", local_ips)
    print ("Setting links = ", links)
    print ("Setting ip_to_city_idx = ", ip_to_city_idx)

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """
    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    packet = event.parsed
 
    self.macToPort[packet.src] = event.port # 1
    if type(packet.next) == arp:
        dst_ip = packet.next.protodst
    else:
        dst_ip = packet.next.dstip

    local_idx = None
    for idx in range(len(self.local_ips)):
        if self.local_ips[idx] == dst_ip:
            local_idx = idx

    if local_idx == None:
        # This means packet 
        dst_city_idx = self.ip_to_city_idx[str(dst_ip)]
        port = self.links[dst_city_idx]
    else:
        port = local_idx + 1 
       
    log.debug("installing flow for <SRCIP>.%i -> %s.%i" %
              (event.port, dst_ip, port))
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet, event.port)
    msg.idle_timeout = 10
    msg.hard_timeout = 30
    msg.actions.append(of.ofp_action_output(port = port))
    msg.data = event.ofp # 6a
    self.connection.send(msg)

class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """

  def read_latency_config(self):
    with open("/tmp/latency_cfg.yaml") as f:
      cfg = yaml.load(f)
    return cfg

  def __init__ (self, transparent, ignore = None):
    """
    Initialize

    See LearningSwitch for meaning of 'transparent'
    'ignore' is an optional list/set of DPIDs to ignore
    """
    core.openflow.addListeners(self)
    self.transparent = transparent
    self.ignore = set(ignore) if ignore else ()

    self.ip_to_city_idx = {}
    self.dpid_to_local_ips = {}
    self.latency_cfg = self.read_latency_config()
    self.next_link_available = {}
    self.links = {}
    for city_idx in range(len(self.latency_cfg)):
        city_cfg = self.latency_cfg[city_idx]
        broker_ip = city_cfg["broker"]
        client_ips = [x for x  in city_cfg["clients"]]
        local_ips = [broker_ip]
        local_ips += client_ips
        dpid = city_idx + 1
        self.dpid_to_local_ips[dpid] = local_ips
        self.next_link_available[city_idx] = len(local_ips)+1
        self.links[city_idx] = {}
        for ip in local_ips:
            self.ip_to_city_idx[ip] = city_idx

    # Now extract the link number information
    for city_idx in range(len(self.latency_cfg)):
        for peer_city_idx in range(len(self.latency_cfg)):
            if peer_city_idx <= city_idx:
                # ignore this combination
                continue
            # Add link
            link = self.next_link_available[city_idx]
            self.next_link_available[city_idx] += 1
            peer_link = self.next_link_available[peer_city_idx]
            self.next_link_available[peer_city_idx] += 1

            self.links[city_idx][peer_city_idx] = link
            self.links[peer_city_idx][city_idx] = peer_link

  def _handle_ConnectionUp (self, event):
    if event.dpid in self.ignore:
      log.debug("Ignoring connection %s" % (event.connection,))
      return
    print ("CONNECTEION RECEIVED on SW with DPID = %s"%event.dpid)
    log.info("Connection %s" % (event.connection,))
    dpid = int(event.dpid)
    city_idx = dpid-1
    LearningSwitch(event.connection, self.transparent, self.dpid_to_local_ips[dpid], self.links[city_idx], self.ip_to_city_idx)


def launch (transparent=False, hold_down=_flood_delay, ignore = None):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  if ignore:
    ignore = ignore.replace(',', ' ').split()
    ignore = set(str_to_dpid(dpid) for dpid in ignore)

  core.registerNew(l2_learning, str_to_bool(transparent), ignore)
