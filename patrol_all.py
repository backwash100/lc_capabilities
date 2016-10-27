###############################################################################
# Metadata
'''
LC_PATROL_MTD_START
{
    "description" : "Collection of all core LimaCharlie detections and hunters.",
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