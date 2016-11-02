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
    "type" : "hunter",
    "description" : "Hunter that tries to identify the scope and root of a suspicious executable location.",
    "requirements" : "",
    "feeds" : [],
    "platform" : "all",
    "author" : "maximelb@google.com",
    "version" : "1.0",
    "scaling_factor" : 10000,
    "n_concurrent" : 5,
    "usage" : {}
}
LC_DETECTION_MTD_END
'''
###############################################################################

from beach.actor import Actor
Hunter = Actor.importLib( 'Hunters', 'Hunter' )
_xm_ = Actor.importLib( 'utils/hcp_helpers', '_xm_' )
_x_ = Actor.importLib( 'utils/hcp_helpers', '_x_' )
InvestigationNature = Actor.importLib( 'utils/hcp_helpers', 'InvestigationNature' )
InvestigationConclusion = Actor.importLib( 'utils/hcp_helpers', 'InvestigationConclusion' )
MemoryAccess = Actor.importLib( 'utils/hcp_helpers', 'MemoryAccess' )
MemoryType = Actor.importLib( 'utils/hcp_helpers', 'MemoryType' )
normalAtom = Actor.importLib( 'utils/hcp_helpers', 'normalAtom' )

class BadExecLocHunter ( Hunter ):
    detects = ( 'WinSuspExecLoc',
                'MacSuspExecLoc' )

    def init( self, parameters, resources ):
        super( BadExecLocHunter, self ).init( parameters )
        self.isMitigate = parameters.get( 'is_mitigate', False )

    def investigate( self, investigation, detect ):
        source = detect[ 'source' ].split( ' / ' )[ 0 ]
        inv_id = detect[ 'detect_id' ]
        data = detect[ 'detect' ]
        thisAtom = _x_( data, '?/hbs.THIS_ATOM' )
        parentAtom = _x_( data, '?/hbs.PARENT_ATOM' )
        originAtom = normalAtom( parentAtom )
        pid = _x_( data, '?/base.PROCESS_ID' )

        # First let's dump the history from the sensor since we rely on a lot.
        histResp = investigation.task( 'fetching history', 
                                       source, 
                                       ( 'history_dump', ) )

        # Get the path of the executable.
        suspExec = _x_( data, '?/base.FILE_PATH' )

        # If this is a duplicate investigation abort.
        duplicateInv = investigation.isDuplicate( suspExec, 60 * 60 * 24 )
        if duplicateInv is not False:
            investigation.conclude( 'this is a [duplicate investigation](/detect?id=%s)' % duplicateInv,
                                    InvestigationNature.DUPLICATE,
                                    InvestigationConclusion.NO_ACTION_TAKEN )
            return


        # If this is from a process start, this is the root, otherwise find the root.
        rootEvent = None
        if 'notification.NEW_PROCESS' == detect:
            rootEvent = detect
        else:
            for rootEvent in self.crawlUpParentTree( None, rootAtom = parentAtom ):
                originAtom = normalAtom( _x_( rootEvent, '?/hbs.THIS_ATOM' ) )
                pid = _x_( rootEvent, '?/base.PROCESS_ID' )
                break

        # Report the suspicious executable with a link to explore
        investigation.reportData( '[Explore](/explorer_view?id=%s) suspicious exec events' % originAtom )

        # Wait for history dump to come in.
        histResp.wait( 10 )
        self.sleep( 5 )

        # Let's see if we can find whoever wrote the file there.
        writerAtom = None
        fileCreates = self.getLastNSecondsOfEventsFrom( 600, source, 'notification.FILE_CREATE' )
        for fileCreate in fileCreates:
            if _x_( fileCreate, '?/base.FILE_PATH' ) == suspExec:
                writerAtom = _x_( fileCreate, '?/hbs.PARENT_ATOM' )
                investigation.reportData( '[Explore](/explorer_view?id=%s) the process who wrote it' % originAtom )
                break
        if writerAtom is None:
            investigation.reportData( "Couldn't find the process who wrote the file" )

        # Try to retrieve the file.
        investigation.task( 'Trying to get the file from cache', 
                             source, 
                             ( 'doc_cache_get', '-f', suspExec ),
                             isNeedResp = False )
        investigation.task( 'Trying to get the file from disk', 
                             source, 
                             ( 'file_get', suspExec ),
                             isNeedResp = False )

        # If we are in mitigation mode we'll suspend the process
        if self.isMitigate:
            self.task( 'Suspending PID %s for %s seconds.', 
                       source, 
                       ( 'os_suspend', '-p', pid ),
                       isNeedResp = False )

        # Let's report on all files this has touched.
        childEvents = self.getChildrenAtoms( originAtom, depth = 100 )
        if childEvents is not None:
            investigation.reportData( 'Found the following files impacted\n' +
                self.listToMdTable( [ 'File Path', 'Operation' ], 
                                    [ ( _x_( x, '?/base.FILE_PATH' ), x.keys()[ 0 ] ) for x in childEvents 
                                      if x.keys()[ 0 ].startswith( 'notification.FILE_' ) ] ) )

        investigation.conclude( "Finished investigating",
                                InvestigationNature.OPEN,
                                InvestigationConclusion.REQUIRES_HUMAN )
