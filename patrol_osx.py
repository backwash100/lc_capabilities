###############################################################################
# Metadata
'''
LC_PATROL_MTD_START
{
    "description" : "Collection of all OSX LimaCharlie detections.",
    "author" : "maximelb@google.com",
    "version" : "1.0"
}
LC_PATROL_MTD_END
'''
###############################################################################

#######################################
# stateless/MacSuspExecLoc
# This actor looks for execution from
# various known suspicious locations.
#######################################
Patrol( 'MacSuspExecLoc',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 1000,
        actorArgs = ( 'stateless/MacSuspExecLoc',
                      [ 'analytics/stateless/osx/notification.NEW_PROCESS/suspexecloc/1.0',
                        'analytics/stateless/osx/notification.CODE_IDENTITY/suspexecloc/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )

#######################################
# stateful/MacReconTools
# This actor looks for burst in usage
# of common recon tools used early
# during exploitation.
#######################################
Patrol( 'MacReconTools',
        initialInstances = 2,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 500,
        actorArgs = ( 'stateful/MacReconTools',
                      'analytics/stateful/modules/osx/recontools/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )

#######################################
# stateless/VirusTotalKnownBad
# This actor checks all hashes against
# VirusTotal and reports hashes that
# have more than a threshold of AV
# reports, while caching results.
# Parameters:
# min_av: minimum number of AV reporting
#    a result on the hash before it is
#    reported as a detection.
#######################################
Patrol( 'VirusTotalKnownBad',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 2000,
        actorArgs = ( 'stateless/VirusTotalKnownBad',
                      [ 'analytics/stateless/common/notification.CODE_IDENTITY/virustotalknownbad/1.0',
                        'analytics/stateless/common/notification.OS_SERVICES_REP/virustotalknownbad/1.0',
                        'analytics/stateless/common/notification.OS_DRIVERS_REP/virustotalknownbad/1.0',
                        'analytics/stateless/common/notification.OS_AUTORUNS_REP/virustotalknownbad/1.0' ] ),
        actorKwArgs = {
            'parameters' : { 'qpm' : 1 },
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 2 } )
