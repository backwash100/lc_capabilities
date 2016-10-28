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
    "description" : "Test hunter that tries to gather additional context for a human.",
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

class TestHunter ( Hunter ):
    detects = ( 'TestDetection', )

    def init( self, parameters, resources ):
        super( RPGenericHunter, self ).init( parameters )

    def investigate( self, investigation, detect ):
        source = detect[ 'source' ].split( ' / ' )[ 0 ]
        inv_id = detect[ 'detect_id' ]
        data = detect[ 'detect' ]
        pid = _x_( data, '?/base.PROCESS_ID' )
        thisAtom = _x_( data, '?/hbs.THIS_ATOM' )
        parentAtom = _x_( data, '?/hbs.PARENT_ATOM' )
        originAtom = parentAtom
        originEvent = data

        # Before we investigate we'll try to get some cached information
        investigation.task( 'get the file creations for the next minute', 
                            source, 
                            ( 'exfil_add', 
                              'notification.FILE_CREATE', 
                              '--expire', 
                              60 ),
                            isNeedResp = False )
        investigation.task( 'get udp network connections for the next minute', 
                            source, 
                            ( 'exfil_add', 
                              'notification.NEW_UDP4_CONNECTION', 
                              '--expire', 
                              60 ),
                            isNeedResp = False )
        investigation.task( 'get tcp network connections for the next minute', 
                            source, 
                            ( 'exfil_add', 
                              'notification.NEW_TCP4_CONNECTION', 
                              '--expire', 
                              60 ),
                            isNeedResp = False )
        histResp = investigation.task( 'fetching history', 
                                       source, 
                                       ( 'history_dump', ) )

        # Wait for the history to be flushed
        histResp.wait( 10 )

        # First, let's crawl up the parent events to see if we know
        # what each one is, we're looking for the root event that
        # is well known.
        for parentEvent in self.crawlUpParentTree( None, rootAtom = parentAtom ):
            originAtom = _x_( parentEvent, '?/hbs.THIS_ATOM' )
            originEvent = parentEvent
            parentEventType = parentEvent.keys()[ 0 ]
            investigation.reportData( 'the parent event is *%s*' % ( parentEventType, ), parentEvent )

            # This is likely going to be a process, but we're going to try to be even
            # more generic and just look at the path to see if we know it.
            parentPath = _x_( parentEvent, '?/base.FILE_PATH' )
            if parentPath is None:
                investigation.reportData( 'parent has no path, unsure on how to process it' )
                break

            # Let's see on how many boxes we've seen this path before.
            parentObjInfo = self.getObjectInfo( parentPath, 'FILE_PATH' )
            if parentObjInfo is None:
                investigation.reportData( 'could not find information on path *%s*' % parentPath )

            nLocs = len( parentObjInfo[ 'locs' ] )
            if nLocs > 10:
                investigation.reportData( 'path seems to be well known, we probably found the origin' )
                break
            else:
                investigation.reportData( 'path *%s* observed on %s hosts' % nLocs )
        
        investigation.reportData( '[origin](/explorer_view?id=%s) of bad behavior as far as we can tell' % normalAtom( originAtom ) )

        originPid = _x_( originEvent, '?/base.PROCESS_ID' )

        memMapResp = investigation.task( 'looking for possible malicious code in the origin process', 
                                         source, 
                                         ( 'mem_map', originPid ) )


        # Let's get the list of documents of interest (also cached) created in the last minute.
        lastDocs = self.getLastNSecondsOfEventsFrom( 60, source, 'notification.NEW_DOCUMENT' )
        lastDocs = [ ( _x_( doc, '?/base.FILE_PATH' ),
                       _x_( doc, '?/base.HASH' ) ) for doc in lastDocs ]
        mdDocs = self.listToMdTable( ( 'File', 'Hash' ), lastDocs )
        investigation.reportData( 'found %s documents created in the last minute\n\n%s' % ( len( lastDocs ), mdDocs ) )

        # Let's see if any of the documents are known bad.
        isBadDocFound = False
        for docPath, docHash in lastDocs:
            vtReport, mdVtReport = self.getVTReport( docHash )
            if vtReport is not None and 0 < len( vtReport ):
                isBadDocFound = True
                investigation.reportData( 'the document with hash *%s* has the following virus total hits:\n%s' % mdVtReport )

        if not isBadDocFound:
            investigation.reportData( 'no recent file had hits on virus total' )


        # Check for new code loading
        lastCode = self.getLastNSecondsOfEventsFrom( 60, source, 'notification.CODE_IDENTITY' )
        lastCode = [ ( _x_( code, '?/base.FILE_PATH' ),
                       _x_( code, '?/base.HASH' ) ) for code in lastCode ]
        mdCode = self.listToMdTable( ( 'File', 'Hash' ), lastCode )
        investigation.reportData( 'found %s new pieces of code in the last minute\n\n%s' % ( len( lastCode ), mdCode ) )

        isBadCodeFound = False
        for codePath, codeHash in lastCode:
            vtReport, mdVtReport = self.getVTReport( codeHash )
            if vtReport is not None and 0 < len( vtReport ):
                isBadCodeFound = True
                investigation.reportData( 'the code with hash *%s* has the following virus total hits:\n%s' % mdVtReport )

        if not isBadCodeFound:
            investigation.reportData( 'no recent code had hits on virus total' )


        # Check for rare domains being queried
        lastDns = self.getLastNSecondsOfEventsFrom( 60, source, 'notification.DNS_REQUEST' )
        lastDns = [ _x_( dns, '?/base.DOMAIN_NAME' ) for dns in lastDns ]
        lastDns = [ x for x in lastDns if not self.isAlexaDomain( x ) ]
        mdDns = self.listToMdTable( ( 'Domain', ), lastDns )
        investigation.reportData( 'found %s DNS queries (minus Alexa top million) in the last minute\n\n%s' % ( len( lastDns ), mdDns ) )


        # Check the network activity
        lastConn = self.getLastNSecondsOfEventsFrom( 60, source, 'notification.NEW_TCP4_CONNECTION' )
        lastConn = [ ( _x_( conn, '?/base.PROCESS_ID' ),
                       '%s:%s' % ( _x_( conn, '?/base.SOURCE/base.IP_ADDRESS' ), _x_( conn, '?/base.SOURCE/base.PORT' ) ),
                       '%s:%s' % ( _x_( conn, '?/base.DESTINATION/base.IP_ADDRESS' ), _x_( conn, '?/base.DESTINATION/base.PORT' ) ) ) for conn in lastConn ]
        mdConn = self.listToMdTable( ( 'PID', 'Source', 'Dest' ), lastConn )
        investigation.reportData( 'found %s TCP connections in the last minute\n\n%s' % ( len( lastConn ), mdConn ) )


        # Let's analyze the memory map to see if we can find suspicious memory regions that we could fetch.
        if memMapResp.wait( 120 ):
            memMap = memMapResp.responses.pop()
            suspiciousRegions = []
            memMap = _xm_( memMap, '?/base.MEMORY_MAP' )
            if memMap is not None:
                for region in memMap:
                    if 'base.FILE_PATH' in region or 'base.MODULE_NAME' in region: continue

                    if region[ 'base.MEMORY_ACCESS' ] in ( MemoryAccess.EXECUTE,
                                                           MemoryAccess.EXECUTE_READ,
                                                           MemoryAccess.EXECUTE_WRITE,
                                                           MemoryAccess.EXECUTE_WRITE_COPY,
                                                           MemoryAccess.EXECUTE_WRITE ):
                        suspiciousRegions.append( region )
            if 0 < len( suspiciousRegions ):
                mdRegions = self.listToMdTable( ( 'Base Address', 'Size', 'Type', 'Access' ), 
                                                [ ( hex( _x_( r, 'base.BASE_ADDRESS' ) ),
                                                    hex( _x_( r, 'base.MEMORY_SIZE' ) ),
                                                    MemoryType.lookup[ _x_( r, 'base.MEMORY_TYPE' ) ],
                                                    MemoryAccess.lookup[ _x_( r, 'base.MEMORY_ACCESS' ) ] ) for r in suspiciousRegions ] )
                investigation.reportData( 'suspicious memory regions:\n%s' % mdRegions )
            else:
                investigation.reportData( 'no suspicious memory region found (%s total regions)' % len( memMap ) )
        elif memMapResp.wasReceived:
            investigation.reportData( 'mem map command received by sensor but no response' )
        else:
            investigation.reportData( 'never received confirmation of mem map from sensor' )


        # Concluding the investigation
        investigation.conclude( 'unsure on the nature of this event but lots of context was gathered',
                                InvestigationNature.OPEN,
                                InvestigationConclusion.REQUIRES_HUMAN )
