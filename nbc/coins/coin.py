# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

__all__ = ['Coin', 'satoshi_per_coin']


satoshi_per_coin = 100000000

class Coin(object):
  COINBASE_MATURITY = 4032    # coinbase will be maturity before 4032 blocks
  
  name = None
  symbols = [ ]
  symbol = None
  
  mining_coin_type   = b'\x00'
  currency_coin_type = b'\x00'
  protocol_version   = 0
  
  magic = b'\x00' * 4
  
  def __hash__(self):
    return hash(self.symbol)
  
  def __cmp__(self, other):
    return cmp(self.name,other.name)
  
  def __str__(self):
    return '<%s>' % self.name.capitalize()
