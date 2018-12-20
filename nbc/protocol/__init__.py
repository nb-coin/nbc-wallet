# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

SERVICE_NODE_NETWORK = (1 << 0)
SERVICE_BLOOM        = (1 << 1)

SERVICES = [SERVICE_NODE_NETWORK, SERVICE_BLOOM]

CCODE_REJECT_MALFORMED        = 0x01
CCODE_REJECT_INVALID          = 0x10
CCODE_REJECT_OBSOLETE         = 0x11
CCODE_REJECT_DUPLICATE        = 0x12
CCODE_REJECT_NONSTANDARD      = 0x40
CCODE_REJECT_DUST             = 0x41
CCODE_REJECT_INSUFFICIENTFEE  = 0x42
CCODE_REJECT_CHECKPOINT       = 0x43

CCODES = [CCODE_REJECT_MALFORMED, CCODE_REJECT_INVALID, CCODE_REJECT_OBSOLETE,
          CCODE_REJECT_DUPLICATE, CCODE_REJECT_NONSTANDARD, CCODE_REJECT_DUST,
          CCODE_REJECT_INSUFFICIENTFEE, CCODE_REJECT_CHECKPOINT]

OBJECT_TYPE_ERROR     = 0
OBJECT_TYPE_MSG_TX    = 1
OBJECT_TYPE_MSG_BLOCK = 2

OBJECT_TYPES = [OBJECT_TYPE_ERROR, OBJECT_TYPE_MSG_TX, OBJECT_TYPE_MSG_BLOCK]

# All message formats and exceptions
from .messages import *

# Data typs we pass into messages and exceptions
from .format import BlockHeader, InventoryVector, NetworkAddress, OutPoint, ParameterError, Txn, TxnIn, TxnOut
