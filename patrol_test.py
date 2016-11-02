###############################################################################
# Metadata
'''
LC_PATROL_MTD_START
{
    "description" : "Collection of all test LimaCharlie detections and hunters.",
    "author" : "maximelb@google.com",
    "version" : "1.0"
}
LC_PATROL_MTD_END
'''
###############################################################################

#######################################
# stateless/TestDetection
# This actor simply looks for a
# file_path containing the string
# 'hcp_evil_detection_test' and generates
# a detect and a file_hash tasking for it.
#######################################
Patrol( 'TestDetection',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 1000,
        actorArgs = ( 'stateless/TestDetection',
                      'analytics/stateless/common/notification.NEW_PROCESS/testdetection/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )

#######################################
# hunter/TestHunter
# This hunter demonstrates various types
# of automation possible.
#######################################
Patrol( 'RPGenericHunter',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 10000,
        actorArgs = ( 'hunter/RPGenericHunter',
                      'analytics/hunter/testhunter/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )