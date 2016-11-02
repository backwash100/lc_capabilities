# Copyright 2015 refractionPOINT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################
# Metadata
'''
LC_DETECTION_MTD_START
{
    "type" : "stateful",
    "description" : "Detects bursts of recon tool activity on Mac.",
    "requirements" : "",
    "feeds" : [],
    "platform" : "osx",
    "author" : "maximelb@google.com",
    "version" : "1.0",
    "scaling_factor" : 500,
    "n_concurrent" : 5,
    "usage" : {}
}
LC_DETECTION_MTD_END
'''
###############################################################################

from beach.actor import Actor
ProcessBurst = Actor.importLib( 'analytics/StateAnalysis/descriptors', 'ProcessBurst' )
StatefulActor = Actor.importLib( 'Detects', 'StatefulActor' )

class MacReconTools ( StatefulActor ):
    def initMachines( self, parameters ):
        self.shardingKey = 'agentid'

        reconBurst = ProcessBurst( name = 'mac_recon_burst',
        						   priority = 1,
        						   summary = 'Burst of recon activity',
        						   procRegExp = r'.*/((ifconfig)|(arp)|(route)|(ping)|(traceroute)|(nslookup)|(netstat)|(wget)|(curl))',
        						   nPerBurst = 3,
        						   withinMilliSeconds = 5 * 1000 )
        
        self.addStateMachineDescriptor( reconBurst )