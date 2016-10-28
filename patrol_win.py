###############################################################################
# Metadata
'''
LC_PATROL_MTD_START
{
    "description" : "Collection of all Windows LimaCharlie detections and hunters.",
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
