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
    "description" : "Detects executions with suspicious names on Windows.",
    "requirements" : "",
    "feeds" : [ "notification.NEW_PROCESS",
                "notification.CODE_IDENTITY" ],
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
_xm_ = Actor.importLib( 'utils/hcp_helpers', '_xm_' )

class WinSuspExecName ( StatelessActor ):
    def init( self, parameters, resources ):
        super( WinSuspExecName, self ).init( parameters, resources )
        self.susp = re.compile( r'.*((\.txt)|(\.doc)|(\.rtf)|(\.jpg)|(\.gif)|(\.pdf)|(\.wmi)|(\.avi)|( {5}.*))\.exe', re.IGNORECASE )
        self.rtlo = re.compile( r'.*\xE2\x80\x8F.*' )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data
        
        for filePath in _xm_( event, '?/base.FILE_PATH' ):
            if self.susp.match( filePath ) or self.rtlo.match( filePath ):
                detects.add( 90,
                             'suspicious executable name',
                             event )
