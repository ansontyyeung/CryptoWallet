from hashlib import sha256
import datetime
import Crypto
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import binascii
import json
from urllib.parse import urlparse
import requests
from typing import List


class Transaction:

    def __init__(self, sender, recipient, value):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.fee = self.get_transaction_fee()

    def to_dict(self):
        return ({
            'sender': self.sender,
            'recipient': self.recipient,
            'value': self.value,
            'fee': self.fee
        })

    def add_signature(self, signature):
        self.signature = signature

    def verify_transaction_signature(self):
        if hasattr(self, 'signature'):
            public_key = RSA.import_key(binascii.unhexlify(self.sender))
            verifier = PKCS1_v1_5.new(public_key)
            h = SHA.new(str(self.to_dict()).encode('utf8'))
            return verifier.verify(h, binascii.unhexlify(self.signature))
        else:
            return False

    def to_json(self):
        return json.dumps(self.__dict__, sort_keys=False)

    def get_transaction_fee(self):  # new func
        rate = 0.01
        fee = float(self.value) * float(rate)
        return str(fee)


class Wallet:
    def __init__(self):
        random = Crypto.Random.new().read
        self._private_key = RSA.generate(1024, random)
        self._public_key = self._private_key.publickey()
        self.value = 0

    def sign_transaction(self, transaction: Transaction):
        signer = PKCS1_v1_5.new(self._private_key)
        h = SHA.new(str(transaction.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')

    @property
    def identity(self):
        pubkey = binascii.hexlify(self._public_key.exportKey(format='DER'))
        return pubkey.decode('ascii')

    def update_balance(self, value):
        self.value = value

    def balance(self):
        return self.value


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, difficulty):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = None
        self.merkle_root: str = ""
        self.nonce = 0
        self.difficulty = difficulty

    def to_dict(self):
        return ({
            'index': self.index,
            'transactions': self.transactions,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'nonce': self.nonce,
            'difficulty': self.difficulty
        })

    def to_json(self):
        return json.dumps(self.__dict__)

    def compute_hash(self):
        self.merkle_root = self.find_merkle_root()  # Added by Sunny
        # Hash with index, timestamp, previous_hash, merkle_root, nonce
        # Hash without transactions
        return sha256(str(self.to_dict()).encode()).hexdigest()

    def find_merkle_root(self) -> str:
        ''' method to return merkle root of all transaction in this block'''
        transactions_hash = self.find_transactions_hash(self.transactions)
        root = self.recur_merkle_root(transactions_hash)
        return root

    def hash_sum(self, a, b) -> str:
        '''simple method to get sum hash of two strings'''
        a = str(a).encode()
        b = str(b).encode()
        sumAB = sha256(a + b).hexdigest()
        return sumAB

    def find_transactions_hash(self, transaction: List[str]) -> List[str]:
        '''method to return the hash value of given transaction list'''
        return [sha256(str(transactions).encode()).hexdigest() for transactions in transaction]

    def recur_merkle_root(self, leaves: List[str]):
        ''' recursive method to return merkle root'''
        if len(leaves) <= 1:
            return leaves[0]
        roots = []
        index = 0
        while index < len(leaves):
            a = leaves[index]
            b = leaves[index + 1] if index + 1 < len(leaves) else leaves[index]
            root = self.hash_sum(a, b)
            roots.append(root)
            index += 2
        return self.recur_merkle_root(roots)


class Blockchain:
    nodes = set()
    interet_rate = 0.01

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []
        self.create_genesis_block()
        self.difficulty_info = {'difficulty': 3,  # difficulty_info
                                'accumulated_blocks': len(self.chain),
                                'time_spent': 0, 'previous_time_spent': None,
                                'timestamp': datetime.datetime.now()}

    # modified from lab's version
    def create_genesis_block(self):
        myWallet = Wallet()
        difficulty = 3

        block_reward = Transaction("Block_Reward", myWallet.identity, "5.0").to_json()
        # ______________________________________________________________________________________________________________________________________________
        '''reform the transaction as a list, for the consistency of the transaction in block'''
        transactions = [block_reward]
        # ______________________________________________________________________________________________________________________________________________
        genesis_block = Block(0, transactions, datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"), "0", difficulty)
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block.to_json())

    def add_new_transaction(self, transaction: Transaction):
        if transaction.verify_transaction_signature():
            self.unconfirmed_transactions.append(transaction.to_json())
            return True
        else:
            return False

    def add_block(self, block, proof):
        previous_hash = self.last_block['hash']
        if previous_hash != block.previous_hash:
            return False
        if not self.is_valid_proof(block, proof):
            return False
        block.hash = proof
        self.chain.append(block.to_json())
        return True

    def is_valid_proof(self, block, block_hash):
        return (block_hash.startswith('0' * block.difficulty) and block_hash == block.compute_hash())

    def proof_of_work(self, block):
        block.nonce = 0
        compute_hash = block.compute_hash()
        while not compute_hash.startswith('0' * block.difficulty):
            block.nonce += 1
            compute_hash = block.compute_hash()
        return compute_hash

    # modified from lab's version
    def mine(self, myWallet):
        start = datetime.datetime.now()

        # ______________________________________________________________________________________________________________________________________________
        '''Adding the interest to the client balance whenever there are 10 blocks generated'''
        ntrans = len(self.chain) % 10
        if ntrans == 0 and len(self.chain) != 0:
            addresses = self.get_addresses()
            interest_t = self.add_interest(addresses)
            if interest_t != []:
                for interest in interest_t:
                    self.unconfirmed_transactions.append(interest.to_json())
        # ______________________________________________________________________________________________________________________________________________

        block_reward = Transaction("Block_Reward", myWallet.identity, "5.0").to_json()
        self.unconfirmed_transactions.insert(0, block_reward)
        if not self.unconfirmed_transactions:
            return False

        # ______________________________________________________________________________________________________________________________________________
        '''perform a checking that prevents the client overspent their balance '''
        self.unconfirmed_transactions = self.check_vaild_transcation()
        # ______________________________________________________________________________________________________________________________________________

        new_block = Block(index=self.last_block['index'] + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                          previous_hash=self.last_block['hash'],
                          difficulty=self.difficulty_info['difficulty'])
        proof = self.proof_of_work(new_block)
        if self.add_block(new_block, proof):
            self.unconfirmed_transactions = []

            current_time = datetime.datetime.now()
            self.difficulty_info['time_spent'] += (current_time - start).total_seconds()
            self.difficulty_info['timestamp'] = current_time
            self.difficulty_info['accumulated_blocks'] = len(self.chain)

            # ______________________________________________________________________________________________________________________________________________
            myWallet.value = self.get_balance(myWallet.identity)
            '''After mining, clear all other node's uncomfirmed transaction list'''
            for node in self.nodes:
                requests.put('http://' + node + '/clear_transacrions')
            # ______________________________________________________________________________________________________________________________________________

            return new_block
        else:
            return False

    @property
    def last_block(self):
        return json.loads(self.chain[-1])

    def register_node(self, node_url):
        # Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def consensus(self):
        neighbours = self.nodes
        new_chain = None
        # We're only looking for chains longer than ours
        max_length = len(self.chain)
        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get('http://' + node + '/fullchain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
        # Replace our chain if longer chain is found
        if new_chain:
            self.chain = json.loads(new_chain)
            return True
        return False

    def valid_chain(self, chain):
        # check if a blockchain is valid
        current_index = 0
        chain = json.loads(chain)
        while current_index < len(chain):
            block = json.loads(chain[current_index])
            current_block = Block(block['index'],
                                  block['transactions'],
                                  block['timestamp'],
                                  block['previous_hash'],
                                  block['difficulty'])
            current_block.hash = block['hash']
            current_block.nonce = block['nonce']
            if current_index + 1 < len(chain):
                if current_block.compute_hash() != \
                        json.loads(chain[current_index + 1])['previous_hash']:
                    return False
            if isinstance(current_block.transactions, list):
                for transaction in current_block.transactions:
                    transaction = json.loads(transaction)
                    # skip Block reward because it does not have signature
                    if transaction['sender'] == 'Block_Reward' or transaction['sender'] == 'Interest':
                        continue
                    current_transaction = Transaction(transaction['sender'],
                                                      transaction['recipient'],
                                                      transaction['value'])
                    current_transaction.signature = transaction['signature']
                    # validate digital signature of each transaction
                    if not current_transaction.verify_transaction_signature():
                        return False
                    if not self.is_valid_proof(current_block, block['hash']):
                        return False
            current_index += 1
        return True

    # --------------------------------------------New Functions-------------------------------------------------------

    def sync_transactions(self, self_addr):
        '''method to sync all unconfirmed transactions list, so that all miner could mine those transactions'''
        nodes = [node for node in self.nodes]
        nodes.append(self_addr)
        transaction_lst = []
        for node in nodes:
            response = requests.get('http://' + node + '/get_transactions')
            if response.status_code == 200:
                t = response.json()['transactions']
                for item in t:
                    transaction_lst.append(item)
        self.unconfirmed_transactions = transaction_lst
        return True

    def get_balance(self, address):
        '''method to get the balance from the given address'''
        if len(self.chain) <= 0:
            return 0.0
        balance = 0.0
        for block in self.chain:
            block = json.loads(block)
            transactions = block['transactions']
            for transaction in transactions:
                transaction = json.loads(transaction)
                if transaction['sender'] == address:
                    balance -= (float(transaction['value']) + float(transaction['fee']))
                if transaction['recipient'] == address:
                    balance += float(transaction['value'])
        return balance

    def get_addresses(self):
        '''method to get all of the addresses from the chain'''
        addresses = []
        for block in self.chain:
            block = json.loads(block)
            transactions = block['transactions']
            for transaction in transactions:
                transaction = json.loads(transaction)
                if transaction['sender'] not in addresses \
                        and transaction['sender'] != 'Block_Reward' \
                        and transaction['sender'] != 'Interest':
                    addresses.append(transaction['sender'])
                if transaction['recipient'] not in addresses:
                    addresses.append(transaction['recipient'])
        return addresses

    def add_interest(self, addresses):
        '''method to release interest to coin-holder according to given addresses list '''
        interest_t = []
        if not addresses:
            return interest_t
        for address in addresses:
            balance = self.get_balance(address)
            interest = self.interet_rate * balance
            interest_t.append(Transaction("Interest", address, interest))
        return interest_t

    # prevent over paid
    def check_vaild_transcation(self):  # apply in mine
        '''method to check if the transaction is valid from the balance or not'''
        checked_unconfirmed_transactions = []
        for transaction in self.unconfirmed_transactions:
            trans = json.loads(transaction)
            if trans['sender'] == 'Block_Reward' or trans['sender'] == 'Interest':
                checked_unconfirmed_transactions.append(transaction)
                continue
            temp_balance = self.get_balance(trans['sender']) - float(trans['value']) - float(trans['fee'])
            for checked_transaction in checked_unconfirmed_transactions:
                checked_transaction = json.loads(checked_transaction)
                if checked_transaction['sender'] == trans['sender']:
                    temp_balance -= float(checked_transaction['value'])
                    temp_balance -= float(checked_transaction['fee'])
            if temp_balance >= 0.0:
                checked_unconfirmed_transactions.append(transaction)
        return checked_unconfirmed_transactions

    def check_vaild_transcation2(self, trans):  # apply in add new transaction
        '''method to check if the transaction is valid from the balance or not'''
        temp_balance = self.get_balance(trans['sender']) - float(trans['value']) - float(trans['fee'])
        for transaction in self.unconfirmed_transactions:
            transaction = json.loads(transaction)
            if transaction['sender'] == trans['sender']:
                temp_balance -= float(transaction['value'])
                temp_balance -= float(transaction['fee'])
        if temp_balance >= 0.0:
            return True

    def merkle_path(self, transaction: Transaction):
        '''method to return the path of merkle tree'''
        path = []
        transactionHash = sha256(str(transaction.to_json()).encode()).hexdigest()
        block = self.search_block_by_hash_value(transactionHash)
        leaves = []
        if block:
            for trans in block['transactions']:
                trans = json.loads(trans)
                new_trans = Transaction(trans['sender'], trans['recipient'], trans['value'])
                new_transHash = sha256(str(new_trans.to_json()).encode()).hexdigest()
                leaves.append(new_transHash)
            path = self.recur_merkle_path(leaves, transactionHash, [])
            path.append(block['merkle_root'])
        return path

    def search_block_by_hash_value(self, transaction_hash):
        '''method to return the block that has the same hash value with the given hash value '''
        fullchain = [json.loads(block) for block in self.chain]
        for block in fullchain[::-1]:
            for trans in block['transactions']:
                trans = json.loads(trans)
                new_trans = Transaction(trans['sender'], trans['recipient'], trans['value'])
                new_transHash = sha256(str(new_trans.to_json()).encode()).hexdigest()
                if transaction_hash == new_transHash:
                    return block
        return False

    def hash_sum(self, a, b):
        '''method to return the hash sum value of 2 given hash value'''
        a = str(a).encode()
        b = str(b).encode()
        sumAB = sha256(a + b).hexdigest()
        return sumAB

    def recur_merkle_path(self, leaves, point, path):
        '''recursive method to generate the path of merkle tree'''
        if len(leaves) <= 1:
            return path
        roots = []
        next_point = ""
        index = 0
        while index < len(leaves):
            a = leaves[index]
            b = leaves[index + 1] if index + 1 < len(leaves) else leaves[index]
            root = self.hash_sum(a, b)
            roots.append(root)
            if a == point:
                path.append(["0", a])
                next_point = root
            elif b == point:
                path.append(["1", b])
                next_point = root
            index += 2
        return self.recur_merkle_path(roots, next_point, path)

    def sync_difficulty_info(self, self_addr):
        nodes = [node for node in self.nodes]
        nodes.append(self_addr)
        timestamps = []
        record = []

        for node in nodes:
            response = requests.get('http://' + node + '/difficulty_info')
            if response.status_code == 200:
                rec = response.json()
                record.append(rec)
                timestamps.append(rec['timestamp'])
        rec = record[timestamps.index(max(timestamps))]
        self.difficulty_info['difficulty'] = rec['difficulty']
        self.difficulty_info['accumulated_blocks'] = rec['accumulated_blocks']
        self.difficulty_info['time_spent'] = rec['time_spent']
        self.difficulty_info['previous_time_spent'] = rec['previous_time_spent']
        self.difficulty_info['timestamp'] = rec['timestamp']

        return True

    def cal_difficulty(self, self_addr):
        response = requests.get('http://' + self_addr + '/difficulty_info')
        data = response.json()
        if data['accumulated_blocks'] % 5 == 0:
            if self.difficulty_info['previous_time_spent'] == None:
                self.difficulty_info['difficulty'] = 3
            else:
                time_diff = self.difficulty_info['time_spent'] - self.difficulty_info['previous_time_spent']
                percentage = time_diff / self.difficulty_info['previous_time_spent']

                if (percentage >= 0) and (abs(percentage) > 0.5) and (self.difficulty_info['difficulty'] + 1 <= 6):
                    self.difficulty_info['difficulty'] += 1
                elif (percentage < 0) and (abs(percentage) > 0.5) and (self.difficulty_info['difficulty'] - 1 >= 0):
                    self.difficulty_info['difficulty'] -= 1

            self.difficulty_info['previous_time_spent'] = data['time_spent']
            self.difficulty_info['time_spent'] = 0
            self.difficulty_info['timestamp'] = data['timestamp']