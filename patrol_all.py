###############################################################################
# Metadata
'''
LC_PATROL_MTD_START
{
    "description" : "Collection of all core LimaCharlie detections.",
    "author" : "maximelb@google.com",
    "version" : "1.0"
}
LC_PATROL_MTD_END
'''
###############################################################################

#######################################
# stateless/WinSuspExecLoc
# This actor looks for execution from
# various known suspicious locations.
#######################################
Patrol( 'WinSuspExecLoc',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 1000,
        actorArgs = ( 'stateless/WinSuspExecLoc',
                      [ 'analytics/stateless/windows/notification.NEW_PROCESS/suspexecloc/1.0',
                        'analytics/stateless/windows/notification.CODE_IDENTITY/suspexecloc/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )

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
# stateful/WinDocumentExploit
# This actor looks for various stateful
# patterns indicating documents being
# exploited.
#######################################
Patrol( 'WinDocumentExploit',
        initialInstances = 2,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 500,
        actorArgs = ( 'stateful/WinDocumentExploit',
                      'analytics/stateful/modules/windows/documentexploit/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )

#######################################
# stateful/WinReconTools
# This actor looks for burst in usage
# of common recon tools used early
# during exploitation.
#######################################
Patrol( 'WinReconTools',
        initialInstances = 2,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 500,
        actorArgs = ( 'stateful/WinReconTools',
                      'analytics/stateful/modules/windows/recontools/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )

#######################################
# stateful/WinScriptedPayload
# This actor looks for a payload executing
# under a scripting engine.
#######################################
Patrol( 'WinScriptedPayload',
        initialInstances = 2,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 500,
        actorArgs = ( 'stateful/WinScriptedPayload',
                      'analytics/stateful/modules/windows/scriptedpayload/1.0' ),
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
# stateless/NewObjects
# This actor looks for new objects of
# specifically interesting types.
#######################################
#Patrol( 'NewObjects',
#        initialInstances = 1,
#        maxInstances = None,
#        relaunchOnFailure = True,
#        onFailureCall = None,
#        scalingFactor = 1000,
#        actorArgs = ( 'stateless/NewObjects',
#                      'analytics/stateless/all/newobjects/1.0' ),
#        actorKwArgs = {
#            'parameters' : { 'types' : [ 'SERVICE_NAME', 'AUTORUNS' ],
#                             'db' : SCALE_DB,
#                             'rate_limit_per_sec' : 10,
#                             'max_concurrent' : 5,
#                             'block_on_queue_size' : 200000 },
#            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
#            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
#            'n_concurrent' : 5,
#            'isIsolated' : True } )

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

#######################################
# stateless/WinSuspExecName
# This actor looks for execution from
# executables with suspicious names that
# try to hide the fact the files are
# executables.
#######################################
Patrol( 'WinSuspExecName',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 1000,
        actorArgs = ( 'stateless/WinSuspExecName',
                      [ 'analytics/stateless/windows/notification.NEW_PROCESS/suspexecname/1.0',
                        'analytics/stateless/windows/notification.CODE_IDENTITY/suspexecname/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )

#######################################
# stateless/ShadowVolumeTampering
# This actor looks for execution changing
# the Windows shadow volumes.
#######################################
Patrol( 'ShadowVolumeTampering',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 1000,
        actorArgs = ( 'stateless/ShadowVolumeTampering',
                      [ 'analytics/stateless/windows/notification.NEW_PROCESS/shadowvolumetampering/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )
