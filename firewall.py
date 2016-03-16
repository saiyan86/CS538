from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os

log = core.getLogger()

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp (self, event):
        ''' Add your logic here ... '''        
        msg = of.ofp_flow_mod() #install a flow entry
        msg.priority = 65535
        msg.match.dl_src = EthAddr("00:00:00:00:00:02") #set match condition
        msg.match.dl_dst = EthAddr("00:00:00:00:00:03") #set match condition
        #msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE)) #drop packet
                
        event.connection.send(msg) #send msg

        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    core.registerNew(Firewall)
