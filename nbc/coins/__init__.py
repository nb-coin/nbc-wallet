# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

from .coin import satoshi_per_coin
from .newbitcoin import Newbitcoin
from .newborntoken import Newborntoken

__all__ = [ 'Newbitcoin', 'Newborntoken', 'satoshi_per_coin' ]

Coins = [
  Newbitcoin,
  Newborntoken,
]

def get_coin(name=None, symbol=None):
  if name is None: name = ''
  if symbol is None: symbol = ''
  
  for coin in Coins:
    if name and name.lower() == coin.name or symbol.upper() in coin.symbols:
      return coin
  return None
