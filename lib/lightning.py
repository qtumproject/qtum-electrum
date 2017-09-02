import sys
sys.path.insert(0, "lib/ln")
from .ln import rpc_pb2_grpc, rpc_pb2
import os
from . import keystore, bitcoin, network, daemon, interface
import socket

import concurrent.futures as futures
import time
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer
import json as jsonm
from google.protobuf import json_format

WALLET = None
NETWORK = None

def public_key_to_p2wpkh(public_key):
    return bitcoin.base_encode(b"\x19\x00\x00" + bitcoin.hash_160(public_key) + bitcoin.Hash(b"\x19\x00\x00" + bitcoin.hash_160(public_key))[:4], 58)
    #return bitcoin.hash160_to_b58_address(bitcoin.hash_160(public_key), ADDRTYPE_P2WPKH)

def ConfirmedBalance(json):
  global K_compressed, pubk
  print(json)
  request = rpc_pb2.ConfirmedBalanceRequest()
  json_format.Parse(json, request)
  m = rpc_pb2.ConfirmedBalanceResponse()
  confs = request.confirmations
  witness = request.witness # bool
  m.amount = sum(WALLET.get_balance())
  msg = json_format.MessageToJson(m)
  print("repl", msg)
  return msg
def NewAddress(json):
  print(json)
  request = rpc_pb2.NewAddressRequest()
  json_format.Parse(json, request)
  m = rpc_pb2.NewAddressResponse()
  if request.type == rpc_pb2.NewAddressRequest.WITNESS_PUBKEY_HASH:
    m.address = public_key_to_p2wpkh(K_compressed)
  elif request.type == rpc_pb2.NewAddressRequest.NESTED_PUBKEY_HASH:
    assert False
  elif request.type == rpc_pb2.NewAddressRequest.PUBKEY_HASH:
    m.address = bitcoin.public_key_to_p2pkh(K_compressed)
  else:
    assert False
  msg = json_format.MessageToJson(m)
  print("repl", msg)
  return msg
def FetchRootKey(json):
  print(json)
  request = rpc_pb2.FetchRootKeyRequest()
  json_format.Parse(json, request)
  m = rpc_pb2.FetchRootKeyResponse()
  m.rootKey = K_compressed
  msg = json_format.MessageToJson(m)
  print("repl", msg)
  return msg

cl = rpc_pb2.ListUnspentWitnessRequest
def ListUnspentWitness(json):
  global K_compressed, pubk
  req = cl()
  json_format.Parse(json, req)
  confs = req.minConfirmations
  print("confs", confs)
  unspent = WALLET.get_utxos()
  print("unspent", unspent)
  m = rpc_pb2.ListUnspentWitnessResponse()
  for utxo in unspent:
    print(utxo)
    towire = m.utxos.add()
    towire.value = utxo.value
    towire.outPoint = rpc_pb2.OutPoint()
    towire.outPoint.hash = utxo.hash
    towire.outPoint.index = utxo.index
  #m.utxos[0].value = 
  return json_format.MessageToJson(m)

def q(pubk, cmd='blockchain.address.get_balance'):
  #print(NETWORK.synchronous_get(('blockchain.address.get_balance', [pubk]), timeout=1))
  # create an INET, STREAMing socket
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # now connect to the web server on port 80 - the normal http port
  s.connect(("localhost", 50001))
  i = interface.Interface("localhost:50001:garbage", s)
  i.queue_request(cmd, [pubk], 42) # 42 is id
  i.send_requests()
  time.sleep(.1)
  res = i.get_responses()
  assert len(res) == 1
  print(res[0][1])
  return res[0][1]["result"]

def serve(config):
  server = SimpleJSONRPCServer(('localhost', 8432))
  server.register_function(FetchRootKey)
  server.register_function(ConfirmedBalance)
  server.register_function(NewAddress)
  server.register_function(ListUnspentWitness)
  server.serve_forever()

def test_lightning(wallet, networ, config):
  global WALLET, NETWORK, pubk, K_compressed
  WALLET = wallet
  #assert networ is not None
  NETWORK = networ
  print("utxos", WALLET.get_utxos())

  pubk = wallet.get_addresses()[0]
  print(pubk)
  K_compressed = wallet.keystore.derive_pubkey(False, 0)
  K_compressed = bytes(bytearray.fromhex(K_compressed))

  assert len(K_compressed) == 33, len(K_compressed)

  print(public_key_to_p2wpkh(K_compressed))
  print(q(pubk, 'blockchain.address.listunspent'))

  serve(config)

if __name__ == '__main__':
  serve()
