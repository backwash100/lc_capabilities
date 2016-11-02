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
    "description" : "Reports a hollowed process detect from a sensor.",
    "requirements" : "",
    "feeds" : "notification.NEW_PROCESS",
    "platform" : [ "windows", "linux" ],
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
ObjectTypes = Actor.importLib( 'utils/ObjectsDb', 'ObjectTypes' )
StatelessActor = Actor.importLib( 'Detects', 'StatelessActor' )

class HollowedProcess ( StatelessActor ):
    def init( self, parameters, resources ):
        super( HollowedProcess, self ).init( parameters, resources )

    def process( self, detects, msg ):
        routing, event, mtd = msg.data

        # No validation for now, straight detect
        detects.add( 90, 'signs of process hollowing found in memory', event )