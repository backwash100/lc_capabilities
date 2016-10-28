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
    "description" : "Test detection.",
    "requirements" : "",
    "feeds" : [ "notification.NEW_PROCESS" ],
    "platform" : "common",
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
StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )
ObjectTypes = Actor.importLib( 'utils/ObjectsDb', 'ObjectTypes' )

class TestDetection ( StatelessActor ):
    def init( self, parameters, resources ):
        super( TestDetection, self ).init( parameters, resources )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data
        
        for o in mtd[ 'obj' ].get( ObjectTypes.FILE_PATH, [] ):
            if 'hcp_evil_detection_test' in o:
                detects.add( 0,
                             'test detection detected',
                             event )
                self.log( "test detection triggered" )
                break
