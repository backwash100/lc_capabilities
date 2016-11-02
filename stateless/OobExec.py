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
    "type" : "stateless",
    "description" : "Reports out of bound executions from a sensor.",
    "requirements" : "",
    "feeds" : [ "notification.EXEC_OOB" ],
    "platform" : "windows",
    "author" : "maximelb@google.com",
    "version" : "1.0",
    "scaling_factor" : 1000,
    "n_concurrent" : 5,
    "usage" : {}
}
LC_DETECTION_MTD_END
'''
###############################################################################

from beach.actor import Actor
import re
ObjectTypes = Actor.importLib( 'utils/ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )

class OobExec ( StatelessActor ):
    def init( self, parameters, resources ):
        super( OobExec, self ).init( parameters, resources )
        self.dotNet = re.compile( r'.*\\Microsoft.NET\\.*' )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data

        # We can get false positives on executables running .net because of JIT
        if not self.dotNet.match( _x_( event, 'notification.EXEC_OOB/base.FILE_PATH' ) ):
            detects.add( 90, 'execution outside of known modules detected in memory', event )
