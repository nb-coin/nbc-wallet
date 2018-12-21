# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import sys, os, time, struct, traceback
from binascii import hexlify, unhexlify
import requests

from nbc import util

from nbc import coins
from nbc import wallet
from nbc import protocol
from nbc import script

def ORD(ch):   # compatible to python3
  return ch if type(ch) == int else ord(ch)

def CHR(i):    # compatible to python3
  return bytes(bytearray((i,)))

def hash_str(s):  # s is bytes, return str type
  return hexlify(s).decode('latin-1')

def fine_print(value):
  s = '%.8f' % (value/100000000,)
  if s.find('.') >= 0:
    s = s.rstrip('0')
    if s[-1] == '.': s = s[:-1]
  return s

def special_int(s):
  if not s: return 0
  if s[-1] == '-':
    return int('-' + s[:-1])
  else: return int(s)

class WalletApp(object):
  SHEET_CACHE_SIZE = 16
  
  WEB_SERVER_ADDR = ''
  
  def __init__(self, wallet, vcn=0, coin=coins.Newbitcoin):
    self._wallet = wallet
    self._vcn = vcn
    self._coin = coin
    
    self._sequence = 0
    self._wait_submit = []
  
  def get_reject_msg_(self, r):
    sErr = None
    if r.status_code == 400:
      msg_err = protocol.Message.parse(r.content,self._coin.magic)
      if msg_err.command == protocol.UdpReject.command:
        sErr = msg_err.message
        if type(sErr) != str:
          sErr = sErr.decode('latin-1')
    return sErr or 'Meet unknown error'
  
  def prepare_txn1_(self, pay_to, ext_in, scan_count, min_utxo, max_utxo, sort_flag, from_uocks):
    if not self.WEB_SERVER_ADDR: return None
    
    self._sequence = self._sequence + 1
    pay_from = [ protocol.format.PayFrom(0,self._wallet.address()) ]
    if ext_in:
      for item in ext_in:
        if isinstance(item,_list_types):
          pay_from.append(protocol.format.PayFrom(item[0],item[1]))
        else: pay_from.append(item)
    if from_uocks is None:
      from_uocks = [0 for item in pay_from]
    pay_to = [protocol.format.PayTo(int(v*100000000),a) for (a,v) in pay_to]
    return protocol.MakeSheet(self._vcn,self._sequence,pay_from,pay_to,scan_count,min_utxo,max_utxo,sort_flag,from_uocks)
  
  def prepare_txn2_(self, protocol_id, str_list, scan_count, min_utxo, max_utxo, sort_flag, from_uock):
    if not self.WEB_SERVER_ADDR: return None
    
    str_list2 = []
    ii = 0               # 0x00000010 PUSH <MSG> PUSH <locate> PUSH <utf8-message>
    for s in str_list:   # 0x00000010 PUSH <PROOF> PUSH <locate> PUSH <hash32>
      if type(s) != bytes:
        s = s.encode('utf-8')
      if len(s) > 75:    # msg length must < 76 (OP_PUSHDATA1)
        print('Error: item of RETURN list should be short than 75 bytes')
        return None
      ii += len(s) + 2   # 2 is OP_PUSH(1) + LEN(1)
      if ii > 84:        # RETURN(1) + B(1) + ID(4) + 84 = 90
        print('Error: RETURN list exceed max byte length')
        return None
      str_list2.append(s)
    
    self._sequence = self._sequence + 1
    pay_from = [ protocol.format.PayFrom(0,self._wallet.address()) ]
    
    ex_args = []; ex_format = ''
    for s in str_list2:
      ex_format += 'BB%is' % len(s)
      ex_args.extend([76,len(s),s])    # 0x4c=76 is OP_PUSHDATA1
    ex_msg = struct.pack('<BBI'+ex_format,106,4,protocol_id,*ex_args) # 0x6a=106 is OP_RETURN
    pay_to = [protocol.format.PayTo(0,ex_msg)]  # value=0 means using RETURN script 
    
    return protocol.MakeSheet(self._vcn,self._sequence,pay_from,pay_to,scan_count,min_utxo,max_utxo,sort_flag,[from_uock])
  
  def submit_txn_(self, msg, submit):
    headers = {'Content-Type': 'application/octet-stream'}
    r = requests.post(self.WEB_SERVER_ADDR + '/txn/sheets/sheet',data=msg.binary(self._coin.magic),headers=headers,timeout=30)
    
    if r.status_code == 200:
      msg2 = protocol.Message.parse(r.content,self._coin.magic)
      if msg2.command == protocol.OrgSheet.command:
        # assert(msg2.sequence == self._sequence)
        
        # step 1: check message is not imitation
        # wait to do: verify msg.signature ...
        
        # check pay_to balance
        coin_hash = self._wallet.publicHash() + self._wallet.coin_type
        d = {}
        for p in msg.pay_to:
          if p.value != 0 or p.address[0:1] != b'\x6a':  # not OP_RETURN
            d[util.base58.decode_check(p.address)[1:]] = p.value
        for idx in range(len(msg2.tx_out)):
          item = msg2.tx_out[idx]
          if item.value == 0 and item.pk_script[0:1] == b'\x6a':   # OP_RETURN
            continue  # ignore
          
          addr = script.get_script_address(item.pk_script,None)
          if not addr:
            print('Error: invalid output address (idx=%i)' % (idx,))
            return 0
          else:
            value_ = d.pop(addr,None)
            if item.value != value_:
              if (value_ is None) and addr[2:] == coin_hash:
                pass
              else:
                print('Error: invalid output value (idx=%i)' % (idx,))
                return 0
        
        for addr in d.keys():
          if coin_hash != addr[2:]:   # the left address should be pay-to-self
            print('Error: unknown output address (%s)' % (hexlify(addr),))
            return 0                  # be ensure not pay to unexpected person
        
        # step 2: sign first pks_out (numbers of tx_in)
        pks_out0 = msg2.pks_out[0].items; pks_num = len(pks_out0)
        tx_ins2 = []
        pub_key = self._wallet.publicKey()
        for (idx,tx_in) in enumerate(msg2.tx_in):   # sign every inputs
          if idx < pks_num:
            hash_type = 1
            payload = script.make_payload(pks_out0[idx],msg2.version,msg2.tx_in,msg2.tx_out,0,idx,hash_type)  # lock_time=0
            sig = self._wallet.sign(payload) + CHR(hash_type)
            sig_script = CHR(len(sig)) + sig + CHR(len(pub_key)) + pub_key
            tx_ins2.append(protocol.TxnIn(tx_in.prev_output,sig_script,tx_in.sequence))
          else: tx_ins2.append(tx_in)
        
        # step 3: make payload and submit
        txn = protocol.Transaction(msg2.version,tx_ins2,msg2.tx_out,msg2.lock_time,b'') # sig_raw = b''
        payload = txn.binary(self._coin.magic)
        hash_ = util.sha256d(payload[24:-1])   # exclude sig_raw
        
        state_info = [msg2.sequence,txn,'requested',hash_,msg2.last_uocks]
        self._wait_submit.append(state_info)
        while len(self._wait_submit) > self.SHEET_CACHE_SIZE:
          del self._wait_submit[0]
        
        if submit:
          unsign_num = len(msg2.tx_in) - pks_num
          if unsign_num != 0:  # leaving to sign
            print('Warning: some input not signed: %i' % (unsign_num,))
            # return 0
          else:
            r2 = requests.post(self.WEB_SERVER_ADDR + '/txn/sheets/txn',data=txn.binary(self._coin.magic),headers=headers,timeout=30)
            if r2.status_code == 200:
              msg3 = protocol.Message.parse(r2.content,self._coin.magic)
              if msg3.command == protocol.UdpConfirm.command and msg3.hash == hash_:
                state_info[2] = 'submited'
                return msg2.sequence
              # else: return 0     # meet unexpected error
            else:
              print('Error: ' + self.get_reject_msg_(r2))
              # return 0
        else: return msg2.sequence
    
    else:
      print('Error: ' + self.get_reject_msg_(r))
    
    return 0
  
  def query_sheet(self, pay_to, ext_in=None, submit=True, scan_count=0, min_utxo=0, max_utxo=0, sort_flag=0, from_uocks=None):
    msg = self.prepare_txn1_(pay_to,ext_in,scan_count,min_utxo,max_utxo,sort_flag,from_uocks)
    if not msg: return 0
    return self.submit_txn_(msg,submit)
  
  def query_sheet_ex(self, protocol_id, str_list, submit=True, scan_count=0, min_utxo=0, max_utxo=0, sort_flag=0, from_uock=0):
    msg = self.prepare_txn2_(protocol_id,str_list,scan_count,min_utxo,max_utxo,sort_flag,from_uock)
    if not msg: return 0
    return self.submit_txn_(msg,submit)
  
  def submit_again(self, sn):
    for state_info in self._wait_submit:
      if state_info[0] == sn:
        txn, old_state, hash_ = state_info[1:4]
        
        headers = {'Content-Type': 'application/octet-stream'}
        r2 = requests.post(self.WEB_SERVER_ADDR + '/txn/sheets/txn',data=txn.binary(self._coin.magic),headers=headers,timeout=30)
        if r2.status_code == 200:
          msg3 = protocol.Message.parse(r2.content,self._coin.magic)
          if msg3.command == protocol.UdpConfirm.command and msg3.hash == hash_:
            state_info[2] = state = 'submited'
            return state
        else:
          print('Error: ' + self.get_reject_msg_(r2))
        break
    
    return 'unknown'
  
  def submit_info(self, sn):
    for (sn2,txn,state,hash2,uocks) in self._wait_submit:
      if sn2 == sn:
        return (txn,state,hash2,uocks)
    return (None,'unknown',None,None)
  
  def submit_state(self, sn):
    for (sn2,txn,state,hash2,uocks) in self._wait_submit:
      if sn2 == sn:
        return state
    return 'unknown'
  
  def confirm_state(self, hash_):  # try update confirm state
    if type(hash_) != bytes:
      hash_ = hash_.encode('latin-1')
    hash2 = hexlify(hash_).decode('latin-1')
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.get(self.WEB_SERVER_ADDR + '/txn/sheets/state',params={'hash':hash2},headers=headers,timeout=30)
    if r.status_code == 200:
      msg3 = protocol.Message.parse(r.content,self._coin.magic)
      if msg3.command == protocol.UdpConfirm.command and msg3.hash == hash_:
        hi  = msg3.arg & 0xffffffff
        num = (msg3.arg >> 32) & 0xffff
        idx = (msg3.arg >> 48) & 0xffff
        state = 'confirm=%i, height=%i, index=%i' % (num,hi,idx)
        return state
    else:
      sErr = self.get_reject_msg_(r)
      if sErr == 'in pending state':
        return 'pending'           # peer has received it but still in waiting publish
      else: print('Error: ' + sErr)
    return 'unknown'
  
  def confirm_state_sn(self, sn):  # try update confirm state
    for state_info in self._wait_submit:
      if state_info[0] != sn: continue
      
      state_ = state_info[2]  # state_info: (sn2,txn,state_,hash_,uocks)
      if state_ == 'submited' or state_[:8] == 'confirm=':
        state = self.confirm_state(state_info[3])
        if state[:8] == 'confirm=':
          state_info[2] = state
        return state
      break
    
    return 'unknown'
  
  def account_state(self, uock_from=0, uock_before=0, another=None): # try query all UTXO if there is not much
    # get account:bytes and account2:str
    account = another if another else self._wallet.address()
    if type(account) == bytes:
      account2 = account.decode('latin-1')
    else:  # account should be str type
      account2 = account
      account = account.encode('latin-1')
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.get(self.WEB_SERVER_ADDR + '/txn/state/account',params={'addr':account2,'uock':uock_from,'uock2':uock_before},headers=headers,timeout=30)
    if r.status_code == 200:
      msg = protocol.Message.parse(r.content,self._coin.magic)
      if msg.command == protocol.AccState.command:
        if msg.account == account:  # msg.link_no is peer's node._link_no
          total = sum(u.value for u in msg.found)
          sDesc = 'Total unspent: %s' % (fine_print(total),)
          if len(msg.found) == msg.search:    # meet limit, should have more UTXO
            sDesc += ' (not search all yet)'
          
          print('Public address: %s' % (account2,))
          print(sDesc)
          print('List of (uock,height,value):' + ('' if msg.found else ' none'))
          for u in msg.found:
            print('  %14s, %10s, %14s' % (u.uock,u.height,fine_print(u.value)))
          print('')
    else:
      print('Error: ' + self.get_reject_msg_(r))
  
  def block_state(self, block_hash, heights=None):  # block_hash should be str or None
    if block_hash:
      if type(block_hash) != bytes:
        block_hash = block_hash.encode('latin-1')
      hash2 = hexlify(block_hash).decode('latin-1')
    else: hash2 = '00' * 32
    
    if heights:
      heights = [special_int(hi) for hi in heights]
    else: heights = []
    
    if not block_hash and not heights:
      print('warning: nothing to query.')
      return
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    account = self._wallet.address()
    if type(account) == bytes:
      account2 = account.decode('latin-1')
    else: account2 = account  # account2 should be str type
    
    r = requests.get(self.WEB_SERVER_ADDR + '/txn/state/block',params={'hash':hash2,'hi':heights},headers=headers,timeout=30)
    if r.status_code == 200:
      msg = protocol.Message.parse(r.content,self._coin.magic)
      if msg.command == protocol.ReplyHeaders.command:
        if not msg.headers:
          print('no block is found!')
        else:
          for (idx,block) in enumerate(msg.headers):
            hi = msg.heights[idx]
            txck = msg.txcks[idx]
            
            print('Block(height=%i,txck=%i):' % (hi,txck))
            print('  hash: %s' % (hash_str(block.hash),))
            print('  version: %i' % (block.version,))
            print('  link_no: 0x%x' % (block.link_no,))
            print('  prev_block:  %s' % (hash_str(block.prev_block),))
            print('  merkle_root: %s' % (hash_str(block.merkle_root),))
            print('  timestamp: %i' % (block.timestamp,))
            print('  bits:  %i' % (block.bits,))
            print('  nonce: %i' % (block.nonce,))
            print('  miner: %s' % (hash_str(block.miner),))
            print('  txn_count: %i' % (block.txn_count,))
            print('')
    else:
      print('Error: ' + self.get_reject_msg_(r))
  
  def utxo_state(self, uocks=5, address=None):  # query txns in list or num of txns
    if type(uocks) == int:
      num = uocks
      uocks = []
    else:
      num = 0
      uocks = list(uocks)     # [uock1,uock2, ...]
    
    if not address:
      account = self._wallet.address()
    else: account = address
    if type(account) == bytes:
      account2 = account.decode('latin-1')
    else: account2 = account  # account2 should be str type
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.get(self.WEB_SERVER_ADDR + '/txn/state/uock',params={'addr':account2,'num':num,'uock':uocks},headers=headers,timeout=30)
    if r.status_code == 200:
      msg = protocol.Message.parse(r.content,self._coin.magic)
      if msg.command == protocol.UtxoState.command:
        for (idx,txn) in enumerate(msg.txns):
          hi = msg.heights[idx]
          flag = msg.indexes[idx]   # flag: higher 16 bits is txns[index], lower 16 bits is out[index]
          curr_idx = flag & 0xffff
          
          print('Block(height=%i)[%i]:' % (hi,(flag >> 16) & 0xffff))
          print('  lock: 0x%x' % (txn.lock_time,))
          
          for (idx2,item2) in enumerate(txn.tx_in):
            print('  in[%i].prev.hash:\n    %s' % (idx2,hash_str(item2.prev_output.hash)))
            print('  in[%i].prev.index: %i' % (idx2,item2.prev_output.index))
          for (idx2,item2) in enumerate(txn.tx_out):
            ss = '*' if curr_idx == idx2 else ''
            print('  %sout[%i].value: %s' % (ss,idx2,fine_print(item2.value)))
            tok = script.Tokenizer(item2.pk_script)
            print('  %sout[%i].script:\n    %s' % (ss,idx2,tok))
          print('')
    else:
      print('Error: ' + self.get_reject_msg_(r))

#=============================

app = None    # for debugging
WalletApp.WEB_SERVER_ADDR = 'https://api.nb-coin.com'

import getpass, shutil, click
from binascii import hexlify, unhexlify

class _Help:
  account     = 'change to account'
  password    = 'password for the account'
  trace_state = 'trace transaction state'
  break_loop  = '\npress Ctrl+C to break query loop, transaction starting ...\n'
  
  used_cfg    = ''

_BASE58_CHAR = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_TX_TRANSFER_MAX = 1000000000000     # 10000 NBC

@click.group()
def cmd_line():
  pass

#--- task: create account ---
@cmd_line.command()
@click.option('--password','-p',prompt=True,hide_input=True,help=_Help.password)
@click.option('--private',default=False,is_flag=True,help='paste or input private key')
@click.argument('name')
def create(password, private, name):
  name = name.split('/').pop().strip()
  if not name:
    print('Error: argument NAME can not be empty')
    return
  
  if private:
    pri = getpass.getpass('Private key:')
    try:
      pri2 = unhexlify(pri)
      if len(pri2) != 32: raise Exception('invalid private key')  # pure 32 bytes private key
      pri2 = util.key.privkey_to_wif(pri2 + b'\x01')  # b'\x01' means compressed
      addr = wallet.Address(priv_key=pri2)
    except:
      print('Error: import private key failed (%s)' % (pri,))
      return
  else: addr = wallet.Address.generate()
  
  sPath = './data/account'
  if not os.path.exists(sPath):
    os.makedirs(sPath)
  sPath = os.path.join(sPath,name + '.cfg')
  
  wallet.saveTo(sPath,addr,password)
  print('Create account and save successful: %s' % (sPath,))
  sAddr = addr.address()
  if type(sAddr) == bytes:
    sAddr = sAddr.decode('latin-1')
  print('Public address is: %s' % (sAddr,))
  
  shutil.copyfile(sPath,'./data/default.cfg')
  print('Default wallet is set to: %s\n' % (sPath,))

#--- task: show account info ---
def read_account_(account, password, printAlias):
  account = account.split('/').pop().strip()
  if not account:
    sPath = './data/default.cfg'
  else:
    sPath = os.path.join('./data/account',account + '.cfg')
  addr = wallet.loadFrom(sPath,password)
  
  if account:
    shutil.copyfile(sPath,'./data/default.cfg')
    print('Default wallet is set to: %s\n' % (sPath,))
    if printAlias: _Help.used_cfg = account
  else:
    if printAlias:
      try:
        sNow = open(sPath,'r').read()
        sBase = './data/account'
        for sFile in os.listdir(sBase):
          if sFile[:1] == '.' or sFile.split('.').pop() != 'cfg': continue
          sCfgFile = os.path.join(sBase,sFile)
          if os.path.isdir(sCfgFile): continue
          
          if sNow == open(sCfgFile,'r').read():
            _Help.used_cfg = sFile.split('.')[0]
            break
      except: pass
  
  if printAlias and _Help.used_cfg:
    print('Using wallet: <%s>' % (_Help.used_cfg,))
  return addr

@cmd_line.command()
@click.option('--account','-a',default='',help=_Help.account)
@click.option('--password','-p',prompt=True,hide_input=True,help=_Help.password)
@click.option('--private',default=False,is_flag=True,help='show private key, be careful!')
@click.option('--public',default=False,is_flag=True,help='show public address')
@click.option('--after',type=click.INT,default=0,help='find from uock (not includes this)')
@click.option('--before',type=click.INT,default=0,help='find before uock (includes this)')
@click.argument('address',nargs=-1)
def info(account, password, private, public, after, before, address):
  global app
  addr = read_account_(account,password,not address)
  
  if public:
    sAddr = addr.address()
    if type(sAddr) == bytes:
      sAddr = sAddr.decode('latin-1')
    print('Public address: %s' % (sAddr,))
    return
  
  if private:
    sPri = hexlify(addr._get_priv())     # get pure private key, 32 bytes
    if type(sPri) != str: sPri = sPri.decode('latin-1')
    print('Private key: %s' % (sPri,))
    return
  
  app = WalletApp(addr,vcn=0)
  if address:
    app.account_state(after,before,address[0])
  else:
    app.account_state(after,before)

#--- task: show block info ---
@cmd_line.command()
@click.option('--account','-a',default='',help=_Help.account)
@click.option('--password','-p',prompt=True,hide_input=True,help=_Help.password)
@click.option('--hash',default='',help='get block by hash')
@click.argument('height',nargs=-1)      # height1 height2 ...
def block(account, password, hash, height):
  global app
  addr = read_account_(account,password,True)
  
  block_hash = None
  if hash:
    block_hash = unhexlify(hash)
  
  app = WalletApp(addr,vcn=0)
  app.block_state(block_hash,height)

#--- task: show transaction info ---
@cmd_line.command()
@click.option('--account','-a',default='',help=_Help.account)
@click.option('--password','-p',prompt=True,hide_input=True,help=_Help.password)
@click.option('--num','-n',type=click.IntRange(1,100,clamp=True),default=5,help='number (1-50) of transactions')
@click.option('--uock',type=click.INT,default=0,help='utxo composite key')
@click.argument('address',nargs=-1)
def utxo(account, password, num, uock, address):
  global app
  addr = read_account_(account,password,True)
  
  uocks = num
  if uock:            # uock = (txck << 20) + index
    uocks = [uock]    # only query one txn
  
  if address:
    address = address[0]
  else: address = None
  app = WalletApp(addr,vcn=0)
  app.utxo_state(uocks,address)

#--- task: process transaction ---
@cmd_line.command()
@click.option('--account','-a',default='',help=_Help.account)
@click.option('--password','-p',prompt=True,hide_input=True,help=_Help.password)
@click.option('--after',type=click.INT,default=0,help='from uock (not includes this)')
@click.option('--hash',default='',help=_Help.trace_state)
@click.argument('target',nargs=-1)      # account=n account2=n2 ...
def transfer(account, password, after, hash, target):
  global app
  addr = read_account_(account,password,True)
  app = WalletApp(addr,vcn=0)
  
  state = ''
  txn_hash = None
  if hash:
    txn_hash = unhexlify(hash)
  else:
    pay_to = []
    for item in target:
      succ = False
      b = item.split('=')
      if len(b) == 2:
        try:
          targ_addr, f = b[0].strip(), b[1].strip()
          if len(targ_addr) > 32:  # base58 addr must large than 32 bytes
            for ch in targ_addr:
              if ch not in _BASE58_CHAR:
                raise Exception('invalid address')
            f = float(f)
            if 0 < f <= _TX_TRANSFER_MAX:
              pay_to.append((targ_addr,f))
              succ = True
        except: pass
      
      if not succ:
        print('Invalid target: %s' % (item,))
        return
    
    if not pay_to:
      print('warning: pay to nobody')
      return
    
    sn = app.query_sheet(pay_to,from_uocks=[after])
    if sn:
      info = app.submit_info(sn)
      state = info[1]; txn_hash = info[2]; last_uocks = info[3]
      if state == 'submited' and txn_hash:
        sDesc = '\nTransaction state: %s' % (state,)
        if last_uocks: sDesc += ', last uock: %s' % (last_uocks[0],)
        print(sDesc)
        print('Hash: %s' % (hexlify(txn_hash).decode('latin-1'),))
  
  if txn_hash:
    print(_Help.break_loop)
    while True:
      time.sleep(90 if state[:8] == 'confirm=' else 15)
      try:
        state = app.confirm_state(txn_hash)
        print('Transaction state: %s' % (state,))
      except KeyboardInterrupt:
        print('')
        break
      except:
        traceback.print_exc()

#--- task: record <MSG> or <PROOF> ---
@cmd_line.command()
@click.option('--account','-a',default='',help=_Help.account)
@click.option('--password','-p',prompt=True,hide_input=True,help=_Help.password)
@click.option('--proof',default=False,is_flag=True,help='save hash string')
@click.option('--where','-w',default='0',help='location flag')
@click.option('--after',type=click.INT,default=0,help='from uock (not includes this)')
@click.option('--hash',default='',help=_Help.trace_state)
@click.argument('content',nargs=-1)     # line1 line2
def record(account, password, proof, where, after, hash, content):
  global app
  addr = read_account_(account,password,True)
  app = WalletApp(addr,vcn=0)
  
  state = ''
  txn_hash = None
  if hash:
    txn_hash = unhexlify(hash)
  else:
    if not content:
      print('warning: nothing to record')
      return
    content = '\n'.join(content)
    
    if proof:
      sn = app.query_sheet_ex(0,['PROOF',where,content],from_uock=after)
    else: sn = app.query_sheet_ex(0,['MSG',where,content],from_uock=after)
    if sn:
      info = app.submit_info(sn)
      state = info[1]; txn_hash = info[2]; last_uocks = info[3]
      if state == 'submited' and txn_hash:
        sDesc = '\nTransaction state: %s' % (state,)
        if last_uocks: sDesc += ', last uock: %s' % (last_uocks[0],)
        print(sDesc)
        print('Hash: %s' % (hexlify(txn_hash).decode('latin-1'),))
  
  if txn_hash:
    print(_Help.break_loop)
    while True:
      time.sleep(90 if state[:8] == 'confirm=' else 15)
      try:
        state = app.confirm_state(txn_hash)
        print('Transaction state: %s' % (state,))
      except KeyboardInterrupt:
        print('')
        break
      except:
        traceback.print_exc()

if __name__ == '__main__':
  if sys.flags.interactive:
    try:
      cmd_line()
    except SystemExit: pass
  else:
    cmd_line()
