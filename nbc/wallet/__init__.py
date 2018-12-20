# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import json
from .address import Address
from .hdwallet import HDWallet

__all__ = ['Address', 'HDWallet', 'loadFrom', 'saveTo']

def saveTo(fileName, wallet, passphrase=''):
  cfg = wallet.dump_to_cfg(passphrase)
  sCfg = json.dumps(cfg)
  with open(fileName,'w') as f:
    f.write(sCfg)

def loadFrom(fileName, passphrase=''):
  with open(fileName,'r') as f:
    cfg = json.loads(f.read())
    tp = cfg.get('type')
    if tp == 'HD':
      return HDWallet.load_from_cfg(cfg,passphrase)
    elif tp == 'default':
      return Address.load_from_cfg(cfg,passphrase)
    else: raise RuntimeError('unknown config')
