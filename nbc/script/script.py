# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import struct, inspect
from binascii import hexlify

from .bytevector import ByteVector
from . import opcodes

from .. import coins
from .. import protocol
from .. import util

from ..protocol import format

__all__ = [ 'get_script_form', 'get_script_cointype', 'get_script_address',
            'make_payload', 'Script', 'Tokenizer' ]

import six

if six.PY3:
  xrange = range
  
  def make_long(x):
    return int(x)

else:
  make_long = long

def ORD(ch):   # compatible to python3
  return ch if type(ch) == int else ord(ch)

def CHR(i):    # compatible to python3
  return bytes(bytearray((i,)))

# Convenient constants

_0 = b'\x00' * 32                 # 32 bytes buffer
_MAX_SIGOPS = 20

Zero = ByteVector.from_value(0)
One = ByteVector.from_value(1)

def _is_pubkey(opcode, bytes_, data):
  if opcode != Tokenizer.OP_LITERAL:
    return False
  if len(data) != 65 or data[0:1] != b'\x04':
    return False
  return True

def _is_hash160(opcode, bytes_, data):
  if opcode != Tokenizer.OP_LITERAL:
    return False
  if len(data) != 20:
    return False
  return True

def _is_coin_hash(opcode, bytes_, data):
  if opcode != Tokenizer.OP_LITERAL:
    return False
  if len(data) <= 34:
    return False
  return True

def _is_protocol_id(opcode, bytes_, data):
  if opcode != Tokenizer.OP_LITERAL:
    return False
  if len(data) != 4:
    return False
  return True

def _is_short_data(opcode, bytes_, data):
  if opcode != Tokenizer.OP_LITERAL:
    return False
  if len(data) > 75:
    return False
  return True

SCRIPT_FORM_NON_STANDARD        = 'non-standard'
SCRIPT_FORM_PAY_TO_PUBKEY_HASH  = 'pay-to-pubkey-hash'
SCRIPT_FORM_PAY_TO_MINERHASH    = 'pay-to-miner-hash'
SCRIPT_FORM_PAY_TO_RETURN       = 'pay-to-return'

# SCRIPT_FORM_UNSPENDABLE       = 'unspendable'
# SCRIPT_FORM_ANYONE_CAN_SPEND  = 'anyone-can-spend'
# SCRIPT_FORM_TRANSACTION_PUZZLE_HASH256 = 'transaction-puzzle-hash256'

STANDARD_SCRIPT_FORMS = [
  SCRIPT_FORM_PAY_TO_PUBKEY_HASH,
  SCRIPT_FORM_PAY_TO_MINERHASH,
  SCRIPT_FORM_PAY_TO_RETURN
]

# @TODO: outdated documentation
# Templates are (name, template) tuples. Each template is a tuple of
# (callable, item1, item2, ...) where callable is called on the entrie
# tokenized script; itemN can be either an opcode or a callable which
# accepts (opcode, bytes, value).

TEMPLATE_PAY_TO_PUBKEY_HASH = ( lambda t: len(t) == 5, opcodes.OP_DUP,
  opcodes.OP_HASH512, _is_coin_hash, opcodes.OP_HASHVERIFY,
  opcodes.OP_CHECKSIG )

TEMPLATE_PAY_TO_MINERHASH = ( lambda t: len(t) == 5, opcodes.OP_DUP,
  opcodes.OP_HASH512, opcodes.OP_MINERHASH, opcodes.OP_EQUALVERIFY,
  opcodes.OP_CHECKSIG )

TEMPLATE_PAY_TO_RETURN = ( lambda t: len(t) >= 4 and len(t) <= 22, opcodes.OP_RETURN, _is_protocol_id,
  _is_short_data,   # push arg1
  _is_short_data,   # push arg2
  _is_short_data,   # push arg3
  _is_short_data,   # push arg4
  _is_short_data,   # push arg5
  _is_short_data,   # push arg6
  _is_short_data,   # push arg7
  _is_short_data,   # push arg8
  _is_short_data,   # push arg9
  _is_short_data )  # push arg10, max support 10 push_data

Templates = [
  (SCRIPT_FORM_PAY_TO_PUBKEY_HASH, TEMPLATE_PAY_TO_PUBKEY_HASH),
  (SCRIPT_FORM_PAY_TO_MINERHASH, TEMPLATE_PAY_TO_MINERHASH),
  (SCRIPT_FORM_PAY_TO_RETURN, TEMPLATE_PAY_TO_RETURN),

#  (SCRIPT_FORM_UNSPENDABLE,
#   (lambda t: True,
#    opcodes.OP_RETURN, )),

#  (SCRIPT_FORM_ANYONE_CAN_SPEND,
#   (lambda t: len(t) == 0, )),

#  (SCRIPT_FORM_TRANSACTION_PUZZLE_HASH256,
#   (lambda t: len(t) == 3,
#    opcodes.OP_HASH256, _is_hash256, opcodes.OP_EQUAL)),
]

def get_script_form(pk_script):
  tokens = Tokenizer(pk_script)
  for (sf, template) in Templates:
    if tokens.match_template(template):
      return sf
  return SCRIPT_FORM_NON_STANDARD

def get_script_cointype(pk_script, coin):
  tokens = Tokenizer(pk_script)
  if tokens.match_template(TEMPLATE_PAY_TO_PUBKEY_HASH):
    coin_hash = tokens.get_value(2).vector
    return coin_hash[34:]
  elif tokens.match_template(TEMPLATE_PAY_TO_MINERHASH):
    return coin.mining_coin_type
  return None

def get_script_address(pk_script, node, block=None):
  tokens = Tokenizer(pk_script)
  if tokens.match_template(TEMPLATE_PAY_TO_PUBKEY_HASH):
    return tokens.get_value(2).vector   # coin_hash = vcn2 + hash32 + cointype
  elif block and tokens.match_template(TEMPLATE_PAY_TO_MINERHASH):
    hi,lo = divmod(node._bind_vcn,256)
    return CHR(lo) + CHR(hi) + block.miner + node.coin.mining_coin_type
  return None

def _stack_op(stack, func):  # replace the top N item from stack with items in the list
  # not enough arguments
  count = len(inspect.getargspec(func).args)
  if len(stack) < count: return False   # False means error
  args = stack[-count:]
  stack[-count:] = []
  
  # add each returned item onto the stack
  for item in func(*args):
    stack.append(item)
  return True

def _math_op(stack, func, check_overflow=True): # replaces the top N items from the stack with the result of callable
  # not enough arguments
  count = len(inspect.getargspec(func).args)
  if len(stack) < count: return False   # False means error
  args = stack[-count:]
  stack[-count:] = []
  
  # check for overflow
  if check_overflow:
    for arg in args:
      if len(arg) > 4: return False
  
  # compute the result
  result = func(*args)
  
  # convert booleans to One or Zero
  if result == True:
    result = One
  elif result == False:
    result = Zero
  
  if result is not None:
    stack.append(result)
  return True

def _hash_op(stack, func):  # replaces the top of the stack with the result of the callable func
  # not enough arguments
  if len(stack) < 1: return False  # error
  
  # hash and push
  value = func(stack.pop().vector)
  stack.append(ByteVector(value))
  return True

def _hash_verify_op(stack):
  if len(stack) < 2: return False    # error
  hash2 = stack.pop().vector
  hash1 = stack.pop().vector
  
  if len(hash2) <= 34: return False  # length of hash mismatch
  return hash1 == hash2[2:34]        # hash2 should be: vcn2 + hash32 + cointype

def make_payload(subscript, txns_ver, txns_in, txns_out, lock_time, input_index, hash_type):
  tx_ins = None; tx_outs = None
  if (hash_type & 0x1f) == 0x01:  # SIGHASH_ALL
    tx_ins = []
    for (index, tx_in) in enumerate(txns_in):
      script = ''
      if index == input_index:
        script = subscript
      
      tx_in = protocol.TxnIn(tx_in.prev_output,script,tx_in.sequence)
      tx_ins.append(tx_in)
    
    tx_outs = txns_out
  
  elif (hash_type & 0x1f) == 0x02: # SIGHASH_NONE (other tx_in.sequence=0,tx_out=[])
    tx_ins = []
    for (index,tx_in) in enumerate(txns_in):
      script = ''
      sequence = 0
      if index == input_index:
        script = subscript
        sequence = tx_in.sequence
      
      tx_in = protocol.TxnIn(tx_in.prev_output,script,sequence)
      tx_ins.append(tx_in)
    
    tx_outs = []
  
  # SIGHASH_SINGLE (len(tx_out)=input_index+1, other outputs=(-1,''), other tx_in.sequence=0)
  elif (hash_type & 0x1f) == 0x03:
    tx_ins = []
    for (index,tx_in) in enumerate(txns_in):
      script = ''
      sequence = 0
      if index == input_index:
        script = subscript
        sequence = tx_in.sequence
      
      tx_in = protocol.TxnIn(tx_in.prev_output,script,sequence)
      tx_ins.append(tx_in)
    
    tx_outs = [ ]
    for (index,tx_out) in enumerate(txns_out):
      if len(tx_outs) > input_index: break
      if index != input_index:
        tx_out = protocol.TxnOut(-1,'')
      tx_outs.append(tx_out)
    else: raise Exception('unknown hash type: %d' % hash_type)
  
  if (hash_type & 0x80) == 0x80:   # SIGHASH_ANYONECANPAY
    tx_in = txn.tx_in[input_index]
    tx_ins = [protocol.TxnIn(tx_in.prev_output,subscript,tx_in.sequence)]
    # tx_outs = txns_out   # tx_outs can be SIGHASH_ALL or SIGHASH_NONE
  
  if tx_ins is None or tx_outs is None:
    raise Exception('invalid signature type')
  
  # FlexTxn same to Txn except that: 1) tx_out can be []  2) no sig_raw
  tx_copy = FlexTxn(txns_ver,tx_ins,tx_outs,lock_time)
  return tx_copy.binary() + struct.pack('<I',hash_type)

def check_signature(signature, public_key, hash_type, subscript, txn, input_index):  # txn is Transaction
  sTail = signature[-1:]
  signature = signature[:-1]
  if hash_type == 0:
    hash_type = ORD(sTail)
  
  payload = make_payload(subscript,txn.version,txn.inputs,txn.outputs,txn.lock_time,input_index,hash_type)
  return util.ecc.verify(payload,public_key,signature)

# identical to protocol.Txn except it allows zero tx_out for SIGHASH_NONE
class FlexTxn(protocol.Txn):
  properties = [
    ('version', format.FtNumber('I')),
    ('tx_in', format.FtArray(format.FtTxnIn, 1)),
    ('tx_out', format.FtArray(format.FtTxnOut)),
    ('lock_time', format.FtNumber('I')),
  ]

class Tokenizer(object):  # Tokenizes a script into tokens, The *VERIFY opcodes are expanded into the two equivalent opcodes
  OP_LITERAL = 0x1ff      # Literals can be accessed with get_value and have the opcode 0x1ff
  
  def __init__(self, script, expand_verify=False):
    self._script = script
    self._expand_verify = expand_verify
    self._tokens = [ ]
    self._process(script)
  
  def append(self, script):
    self._script += script
    self._process(script)
  
  def get_subscript(self, start_index=0, filter=None):  # rebuild the script from token start_index, filter
    output = b''
    for (opcode, bytes_, value) in self._tokens[start_index:]:
      if filter and not filter(opcode,bytes_,value):  # removing tokens that return False
        continue
      output += bytes_
    return output
  
  def match_template(self, template):  # given a template, True if this script matches
    if not template[0](self):  # template[0] is condition, usually checking token number
      return False
    
    # ((opcode, bytes, value), template_target)  # do check by callable or opcode
    for ((o, b, v), t) in zip(self._tokens, template[1:]):
      if callable(t):  # callable, check the value
        if not t(o, b, v):
          return False
      elif t != o:     # otherwise, compare opcode
        return False
    
    return True
  
  _Verify = {
    opcodes.OP_EQUALVERIFY: opcodes.OP_EQUAL,
    opcodes.OP_NUMEQUALVERIFY: opcodes.OP_NUMEQUAL,
    opcodes.OP_CHECKSIGVERIFY: opcodes.OP_CHECKSIG,
    opcodes.OP_CHECKMULTISIGVERIFY: opcodes.OP_CHECKMULTISIG,
  }

  def _process(self, script):  # parse the script into tokens
    while script:
      opcode = ORD(script[0])
      bytes_ = script[0:1]     # for PY2 and PY3
      script = script[1:]
      value = None
      
      verify = False
      if opcode == opcodes.OP_0:
        value = Zero
        opcode = Tokenizer.OP_LITERAL
      elif 1 <= opcode <= 78:  # OP_PUSHDATA1~OP_PUSHDATA4: 76~78
        length = opcode
        
        if opcodes.OP_PUSHDATA1 <= opcode <= opcodes.OP_PUSHDATA4:
          iTmp = opcode - opcodes.OP_PUSHDATA1
          op_length = [1, 2, 4][iTmp]
          format = ['<B', '<H', '<I'][iTmp]
          length = struct.unpack(format, script[:op_length])[0]
          bytes_ += script[:op_length]
          script = script[op_length:]
        
        sTmp = script[:length]
        value = ByteVector(vector=sTmp)
        bytes_ += sTmp
        script = script[length:]
        if len(value) != length:
          raise Exception('not enought script for literal')
        opcode = Tokenizer.OP_LITERAL
      elif opcode == opcodes.OP_1NEGATE:
        opcode = Tokenizer.OP_LITERAL
        value = ByteVector.from_value(-1)
      elif opcode == opcodes.OP_TRUE:
        opcode = Tokenizer.OP_LITERAL
        value = ByteVector.from_value(1)
      elif opcodes.OP_1 <= opcode <= opcodes.OP_16:
        value = ByteVector.from_value(opcode - opcodes.OP_1 + 1) # 1 ~ 16
        opcode = Tokenizer.OP_LITERAL  # take 'push n' as literal
      elif self._expand_verify and opcode in self._Verify:  # split into two tokens
        opcode = self._Verify[opcode]
        verify = True
      
      self._tokens.append((opcode, bytes_, value))
      if verify:
        self._tokens.append((opcodes.OP_VERIFY, b'', None))
  
  def get_bytes(self, index):  # get the original bytes used for the opcode and value
    return self._tokens[index][1]
  
  def get_value(self, index):  # get the value for a literal
    return self._tokens[index][2]
  
  def __len__(self):
    return len(self._tokens)
  
  def __getitem__(self, name):
    return self._tokens[name][0]
  
  def __iter__(self):
    for (opcode, bytes_, value) in self._tokens:
      yield opcode
  
  def __str__(self):
    output = []
    for (opcode, bytes_, value) in self._tokens:
      if opcode == Tokenizer.OP_LITERAL:
        output.append(hexlify(value.vector).decode('latin-1'))
      else:
        if bytes_:
          output.append(opcodes.get_opcode_name(ORD(bytes_[0])))
    return ' '.join(output)

class Script(object):
  def __init__(self, transaction, block_hi, coin):
    self._txn = transaction
    self._block_hi = block_hi
    self._coin = coin
  
  @property
  def output_count(self):
    return len(self._txn.outputs)
  
  def output_addr(self, out_index, blocks, ignore_zero=True):
    po = self._txn.outputs[out_index]
    if ignore_zero and po.value == 0: return None
    
    tokens = Tokenizer(po.pk_script)
    
    if tokens.match_template(TEMPLATE_PAY_TO_PUBKEY_HASH):
      return tokens.get_value(2).vector  # vector is: vcn2 + hash32 + cointype
    
    elif tokens.match_template(TEMPLATE_PAY_TO_MINERHASH):
      if self._txn.index == 0:
        block_ = blocks._get(self._txn._blockid)
        if block_:  # vcn=0, miner is public key hash (32 bytes)
          return b'\x00\x00' + block_.miner + blocks.coin.mining_coin_type
    
    # elif tokens.match_template(TEMPLATE_PAY_TO_RETURN):
    #   return None
    
    return None
  
  def script_form(self, output_index):
    return get_script_form(self._txn.outputs[output_index].pk_script)
  
  def is_standard_script(self, output_index):
    pk_script = self._txn.outputs[output_index]
    tokens = Tokenize(pk_script,expand_verify=False)
    for sf in STANDARD_SCRIPT_FORMS:
      if tokens.match_template(Templates[sf]):
        return True
    return False
  
  @property
  def input_count(self):
    return len(self._txn.inputs)
  
  def verify_input(self, input_index, pk_script, miner=None):
    tx_in = self._txn.inputs[input_index]
    return self.process(tx_in.sig_script,pk_script,self._txn,input_index,0,miner)  # hash_type=0
  
  def verify(self, blocks):
    if self._txn.index == 0: return True  # ignore coinbase input checking
    
    for (i,ins) in enumerate(self._txn.inputs):
      # verify the input with its previous output
      prev_txn = self._txn.previous_txn(i)
      if prev_txn is None:
        return False           # invalid previous txn
      if not prev_txn._mainchain:
        return False           # not in mainchain
      
      miner = None
      if prev_txn.index == 0:  # it is coinbase
        prev_txn_block = blocks._get(prev_txn._blockid)
        if not prev_txn_block: # fatal error
          return False
        if prev_txn_block.height > self._block_hi - self._coin.COINBASE_MATURITY:
          return False         # coinbase not maturity 
        miner = prev_txn_block.miner
      
      output = prev_txn.outputs[ins.prev_output.index]
      if not self.verify_input(i,output.pk_script,miner):
        return False
    
    return True
  
  @staticmethod
  def process(sig_script, pk_script, transaction, input_index, hash_type=0, miner=None):
    # tokenize (placing the last code separator after the signature script)
    tokens = Tokenizer(sig_script,expand_verify=True)
    sig_length = len(tokens)
    tokens.append(pk_script)
    last_codeseparator = sig_length
    
    # print(str(tokens))
    
    # check for VERY forbidden opcodes (see "reserved Words" on the wiki)
    for tok in tokens:
      if tok in (opcodes.OP_VERIF, opcodes.OP_VERNOTIF):
        return False
    
    # stack of entered if statments' condition values
    ifstack = []
    
    # operating stacks
    stack = []
    altstack = []
    
    for pc in xrange(0,len(tokens)):
      opcode = tokens[pc]
      
      # print('STACK:', (opcodes.OPCODE_NAMES[min(opcode, 255)], repr(tokens.get_value(pc))))
      # print('  ' + '\n  '.join('%s (%d)' % (hexlify(t.vector), t.value) for t in stack))
      # print('')
      
      # handle if before anything else
      if opcode == opcodes.OP_IF:
        ifstack.append(stack.pop().value != 0)
      
      elif opcode == opcodes.OP_NOTIF:
        ifstack.append(stack.pop().value == 0)
      
      elif opcode == opcodes.OP_ELSE:
        if len(ifstack) == 0: return False
        ifstack.append(not ifstack.pop())
      
      elif opcode == opcodes.OP_ENDIF:
        if len(ifstack) == 0: return False
        ifstack.pop()
      
      # we are in a branch with a false condition
      if False in ifstack: continue
      
      ### Literals
      
      if opcode == Tokenizer.OP_LITERAL:
        stack.append(tokens.get_value(pc))
      
      ### Flow Control (OP_IF and kin are above)
      
      elif opcode == opcodes.OP_NOP:
        pass
      
      elif opcode == opcodes.OP_VERIFY:
        if len(stack) < 1: return False
        if bool(stack[-1]):
          stack.pop()
        else: return False
      
      elif opcode == opcodes.OP_HASHVERIFY:
        if not _hash_verify_op(stack):
          return False
      
      elif opcode == opcodes.OP_RETURN:
        return False
      
      ### Stack Operations
      
      elif opcode == opcodes.OP_TOALTSTACK:
        if len(stack) < 1: return False
        altstack.append(stack.pop())
      
      elif opcode == opcodes.OP_FROMALTSTACK:
        if len(altstack) < 1: return False
        stack.append(altstack.pop())
      
      elif opcode == opcodes.OP_IFDUP:
        if len(stack) < 1: return False
        if bool(stack[-1]):
          stack.append(stack[-1])
      
      elif opcode == opcodes.OP_DEPTH:
        stack.append(ByteVector.from_value(len(stack)))
      
      elif opcode == opcodes.OP_DROP:
        if not _stack_op(stack, lambda x: [ ]):
          return False
      
      elif opcode == opcodes.OP_DUP:
        if not _stack_op(stack, lambda x: [x, x]):
          return False
      
      elif opcode == opcodes.OP_NIP:    # remove second-to-top item
        if not _stack_op(stack, lambda x1, x2: [x2]):
          return False
      
      elif opcode == opcodes.OP_OVER:   # copy second-to-top item
        if not _stack_op(stack, lambda x1, x2: [x1, x2, x1]):
          return False
      
      elif opcode == opcodes.OP_PICK:   # copy n-to-top item
        if len(stack) < 2: return False
        n = stack.pop().value + 1     # n would be pop-ed
        if not (0 <= n <= len(stack)): return False
        stack.append(stack[-n])
      
      elif opcode == opcodes.OP_ROLL:   # move n-to-top item
        if len(stack) < 2: return False
        n = stack.pop().value + 1     # n would be pop-ed
        if not (0 <= n <= len(stack)): return False
        stack.append(stack.pop(-n))
      
      elif opcode == opcodes.OP_ROT:    # rotate top three items
        if not _stack_op(stack, lambda x1, x2, x3: [x2, x3, x1]):
          return False
      
      elif opcode == opcodes.OP_SWAP:
        if not _stack_op(stack, lambda x1, x2: [x2, x1]):
          return False
      
      elif opcode == opcodes.OP_TUCK:   # top item is copied and insert to second-to-top
        if not _stack_op(stack, lambda x1, x2: [x2, x1, x2]):
          return False
      
      elif opcode == opcodes.OP_2DROP:
        if not _stack_op(stack, lambda x1, x2: []):
          return False
      
      elif opcode == opcodes.OP_2DUP:
        if not _stack_op(stack, lambda x1, x2: [x1, x2, x1, x2]):
          return False
      
      elif opcode == opcodes.OP_3DUP:
        if not _stack_op(stack, lambda x1, x2, x3: [x1, x2, x3, x1, x2, x3]):
          return False
      
      elif opcode == opcodes.OP_2OVER:  # copy the pair of items two spaces back
        if not _stack_op(stack, lambda x1, x2, x3, x4: [x1, x2, x3, x4, x1, x2]):
          return False
      
      elif opcode == opcodes.OP_2ROT:   # move fifth and sixth items to top
        if not _stack_op(stack, lambda x1, x2, x3, x4, x5, x6: [x3, x4, x5, x6, x1, x2]):
          return False
      
      elif opcode == opcodes.OP_2SWAP:  # swap two pairs of items
        if not _stack_op(stack, lambda x1, x2, x3, x4: [x3, x4, x1, x2]):
          return False
      
      ### Splice Operations
      
      elif opcode == opcodes.OP_SIZE:
        if len(stack) < 1: return False
        stack.append(ByteVector.from_value(len(stack[-1])))
      
      ### Bitwise Logic Operations
      
      elif opcode == opcodes.OP_EQUAL:
        if not _math_op(stack, lambda x1, x2: bool(x1 == x2), False):
          return False
      
      ### Arithmetic Operations
      
      elif opcode == opcodes.OP_1ADD:
        if not _math_op(stack, lambda a: a + One):
          return False
      
      elif opcode == opcodes.OP_1SUB:
        if not _math_op(stack, lambda a: a - One):
          return False
      
      elif opcode == opcodes.OP_NEGATE:
        if not _math_op(stack, lambda a: -a):
          return False
      
      elif opcode == opcodes.OP_ABS:
        if not _math_op(stack, lambda a: abs(a)):
          return False
      
      elif opcode == opcodes.OP_NOT:
        if not _math_op(stack, lambda a: bool(a == 0)):
          return False
      
      elif opcode == opcodes.OP_0NOTEQUAL:
        if not _math_op(stack, lambda a: bool(a != 0)):
          return False
      
      elif opcode == opcodes.OP_ADD:
        if not _math_op(stack, lambda a, b: a + b):
          return False
      
      elif opcode == opcodes.OP_SUB:
        if not _math_op(stack, lambda a, b: a - b):
          return False
      
      elif opcode == opcodes.OP_BOOLAND:
        if not _math_op(stack, lambda a, b: bool(a and b)):
          return False
      
      elif opcode == opcodes.OP_BOOLOR:
        if not _math_op(stack, lambda a, b: bool(a or b)):
          return False
      
      elif opcode == opcodes.OP_NUMEQUAL:
        if not _math_op(stack, lambda a, b: bool(a == b)):
          return False
      
      elif opcode == opcodes.OP_NUMNOTEQUAL:
        if not _math_op(stack, lambda a, b: bool(a != b)):
          return False
      
      elif opcode == opcodes.OP_LESSTHAN:
        if not _math_op(stack, lambda a, b: bool(a < b)):
          return False
      
      elif opcode == opcodes.OP_GREATERTHAN:
        if not _math_op(stack, lambda a, b: bool(a > b)):
          return False
      
      elif opcode == opcodes.OP_LESSTHANOREQUAL:
        if not _math_op(stack, lambda a, b: bool(a <= b)):
          return False
      
      elif opcode == opcodes.OP_GREATERTHANOREQUAL:
        if not _math_op(stack, lambda a, b: bool(a >= b)):
          return False
      
      elif opcode == opcodes.OP_MIN:
        if not _math_op(stack, lambda a, b: min(a, b)):
          return False
      
      elif opcode == opcodes.OP_MAX:
        if not _math_op(stack, lambda a, b: max(a, b)):
          return False
      
      elif opcode == opcodes.OP_WITHIN:
        if not _math_op(stack, lambda x, omin, omax: bool(omin <= x < omax)):
          return False
      
      ### Crypto Operations
      
      elif opcode == opcodes.OP_RIPEMD160:
        if not _hash_op(stack, util.ripemd160):
          return False
      
      elif opcode == opcodes.OP_SHA1:
        if not _hash_op(stack, util.sha1):
          return False
      
      elif opcode == opcodes.OP_SHA256:
        if not _hash_op(stack, util.sha256):
          return False
      
      elif opcode == opcodes.OP_HASH160:
        if not _hash_op(stack, util.hash160):
          return False
      
      elif opcode == opcodes.OP_HASH256:
        if not _hash_op(stack, util.sha256d):
          return False
      
      elif opcode == opcodes.OP_HASH512:    # new adding instruction
        if not _hash_op(stack, util.publickey_hash):
          return False
      
      elif opcode == opcodes.OP_MINERHASH:  # new adding instruction
        stack.append(ByteVector(miner or _0))
      
      elif opcode == opcodes.OP_CODESEPARATOR:
        if pc > last_codeseparator:
          last_codeseparator = pc
      
      # see: https://en.bitcoin.it/wiki/OP_CHECKSIG
      elif opcode == opcodes.OP_CHECKSIG:
        if len(stack) < 2: return False
        
        # remove the signature and code separators for subscript
        def filter(opcode, bytes_, value):
          if opcode == opcodes.OP_CODESEPARATOR:
            return False
          if opcode == Tokenizer.OP_LITERAL and isinstance(value,bytes) and value == signature:
            return False
          return True
        subscript = tokens.get_subscript(last_codeseparator,filter) # will filter off OP_CODESEPARATOR and signature-bytes
        
        public_key = stack.pop().vector
        signature = stack.pop().vector
        valid = check_signature(signature, public_key, hash_type, subscript, transaction, input_index)
        
        if valid:
          stack.append(One)
        else: stack.append(Zero)
      
      elif opcode == opcodes.OP_CHECKMULTISIG:
        if len(stack) < 2: return False
        
        # get all the public keys
        count = stack.pop().value
        if count > _MAX_SIGOPS:
          return False
        
        if len(stack) < count: return False
        public_keys = [stack.pop() for i in xrange(count)]
        
        if len(stack) < 1: return False
        
        # get all the signautres
        count = stack.pop().value
        if len(stack) < count: return False
        signatures = [stack.pop() for i in xrange(count)]
        
        # due to a bug in the original client, discard an extra operand
        if len(stack) < 1: return False
        stack.pop()
        
        # remove the signature and code separators for subscript
        def filter(opcode, bytes_, value):
          if opcode == opcodes.OP_CODESEPARATOR:
            return False
          if opcode == Tokenizer.OP_LITERAL and isinstance(value,bytes) and value in signatures:
            return False
          return True
        subscript = tokens.get_subscript(last_codeseparator, filter)
        
        matched = dict()
        for signature in signatures:
          # do any remaining public keys work?
          succ_key = None
          for public_key in public_keys:
            if check_signature(signature, public_key, hash_type, subscript, transaction, input_index):
              succ_key = public_key
              break
          
          # record which public key and remove from future canidate
          if succ_key:
            matched[signature] = succ_key
            public_keys.remove(succ_key)
        
        if len(matched) == len(signatures):  # all signature matched
          stack.append(One)
        else: stack.append(Zero)
      
      elif opcode == opcodes.OP_RESERVED:
        return False
      
      elif opcode == opcodes.OP_VER:
        return False
      
      elif opcode == opcodes.OP_RESERVED1:
        return False
      
      elif opcode == opcodes.OP_RESERVED2:
        return False
      
      elif opcodes.OP_NOP1 <= opcode <= opcodes.OP_NOP7:
        pass
      
      else:
        print('UNKNOWN OPCODE: %d' % opcode)
        return False
    
    # print('LAST STACK:')
    # print('  ' + '\n  '.join(str(v) for v in stack))
    # print('')
    
    if len(stack) and bool(stack[-1]):
      return True
    return False
