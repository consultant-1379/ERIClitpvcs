##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from litp.core.task import RemoteExecutionException


class VCSConfigException(RemoteExecutionException):
    pass


class VCSRuntimeException(RemoteExecutionException):
    pass


class VcsCmdApiException(RemoteExecutionException):
    pass


class VcsMultipleMatchingItemsException(Exception):
    pass


class VcsNonMatchingItemException(Exception):
    pass
