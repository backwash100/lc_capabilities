###############################################################################
# Metadata
'''
LC_PATROL_MTD_START
{
    "description" : "Collection of all sensor LimaCharlie detections and hunters.",
    "author" : "maximelb@google.com",
    "version" : "1.0"
}
LC_PATROL_MTD_END
'''
###############################################################################

#######################################
# stateless/YaraDetects
# This actor generates detects from
# sensor events with Yara detections.
#######################################
Patrol( 'YaraDetects',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 10000,
        actorArgs = ( 'stateless/YaraDetects',
                      'analytics/stateless/common/notification.YARA_DETECTION/yaradetects/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )

#######################################
# stateless/OobExec
# This actor looks OOB execution
# notifications.
#######################################
Patrol( 'OobExec',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 5000,
        actorArgs = ( 'stateless/OobExec',
                      'analytics/stateless/windows/notification.EXEC_OOB/oobexec/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )

#######################################
# stateless/HollowedProcess
# This actor for mismatch between a
# module on disk and in memory for
# signs of process hollowing.
#######################################
Patrol( 'HollowedProcess',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 10000,
        actorArgs = ( 'stateless/HollowedProcess',
                      [ 'analytics/stateless/windows/notification.MODULE_MEM_DISK_MISMATCH/hollowedprocess/1.0',
                        'analytics/stateless/linux/notification.MODULE_MEM_DISK_MISMATCH/hollowedprocess/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5',
            'trustedIdents' : [ 'analysis/038528f5-5135-4ca8-b79f-d6b8ffc53bf5' ],
            'n_concurrent' : 5 } )