from classes import Wallet
from classes import Transaction
from classes import Blockchain
from classes import Block
from flask import Flask, jsonify, request
import requests
import json
from urllib.parse import urlparse

app = Flask(__name__)


@app.route('/new_transaction', methods=["GET", "POST"])
def new_transaction():
    recipient = request.args.get("address")
    amount = request.args.get("amount")

    transaction = Transaction(myWallet.identity,
                              recipient, amount)
    transaction.add_signature(myWallet.sign_transaction(transaction))
    transaction_result = blockchain.add_new_transaction(transaction)
    if transaction_result:
        response = {'message': 'Transaction will be added to Block '}
        return jsonify(response), 201
    else:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406


@app.route('/get_transactions', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain.unconfirmed_transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def part_chain():
    response = {
        'chain': blockchain.chain[-10:],
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


def json_replace(s):
    s = s.replace("\'", "\"")
    s = s.replace("\\", "")
    s = s.replace('\"{', '{').replace('}\"', '}')
    s = s.replace("\"[", "[").replace("]\"", "]")
    return s


@app.route('/fullchainforapp', methods=['GET'])
def full_chain_forapp():
    response = {
        'chain': json_replace(json.dumps(blockchain.chain)),
        'length': len(blockchain.chain)
    }
    result = str(response)
    return json_replace(result), 200


@app.route('/fullchain', methods=['GET'])
def full_chain():
    response = {
        'chain': json.dumps(blockchain.chain),
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/get_nodes', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/register_node', methods=['POST'])  # request that registrate node B from A
def register_node():
    values = request.form
    node = values.get('node')
    com_port = values.get('com_port')
    # handle type B request
    if com_port is not None:  # for node B, node A's port
        blockchain.register_node(request.remote_addr + ":" + com_port)
        return "ok", 200
    # handle type A request
    if node is None and com_port is None:
        return "Error: Please supply a valid nodes", 400
    blockchain.register_node(node)  # for node A, registration node
    # retrieve nodes list
    node_list = requests.get('http://' + node + '/get_nodes')
    if node_list.status_code == 200:
        node_list = node_list.json()['nodes']
        for node in node_list:
            blockchain.register_node(node)  # update node in blockchain object
    for new_nodes in blockchain.nodes:
        # sending type B request
        requests.post('http://' + new_nodes + '/register_node',
                      data={'com_port': str(port)})  # update node in json
    # check if our chain is authoritative from other nodes
    replaced = blockchain.consensus()
    if replaced:
        response = {
            'message': 'Longer authoritative chain found from peers,'
                       'replacing ours',
            'total_nodes': [node for node in blockchain.nodes]
        }
    else:
        response = {
            'message': 'New nodes have been added, but our chain is'
                       'authoritative',
            'total_nodes': [node for node in blockchain.nodes]
        }
    return jsonify(response), 201


@app.route('/consensus', methods=['GET'])
def consensus():
    replaced = blockchain.consensus()
    if replaced:
        response = {
            'message': 'Our chain was replaced',
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
        }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    blockchain.sync_transactions(request.host)
    newblock = blockchain.mine(myWallet)
    for node in blockchain.nodes:
        requests.get('http://' + node + '/consensus')
    response = {
        'index': newblock.index,
        'transactions': newblock.transactions,
        'timestamp': newblock.timestamp,
        'nonce': newblock.nonce,
        'hash': newblock.hash,
        'merkle_root': newblock.merkle_root,
        'previous_hash': newblock.previous_hash
    }
    nodes = [node for node in blockchain.nodes]  # code on sync difficulty_info
    nodes.append(request.host)
    print(nodes)
    for node in nodes:
        requests.get('http://' + node + '/sync_difficulty_info')

    blockchain.cal_difficulty(request.host)

    for node in blockchain.nodes:
        requests.post('http://' + node + '/update_balance')
    return jsonify(response), 200


##################################### New functions #####################################

@app.route('/get_info', methods=['GET'])
def get_info():
    response = {
        'public_key': myWallet.identity,
        'balance': blockchain.get_balance(myWallet.identity)
    }
    return jsonify(response), 200


@app.route('/sync_transactions', methods=['GET'])
def sync_transactions():
    lst = blockchain.sync_transactions(request.host)
    if lst:
        response = {'message': 'Sync Transaction'}
    else:
        response = {'message': False}
    return jsonify(response), 200


@app.route('/update_balance', methods=['POST'])
def update_balance():
    myWallet.value = blockchain.get_balance(myWallet.identity)
    response = {'message': 'Balance updated'}
    return jsonify(response), 200

@app.route('/lightweight', methods=['GET'])
def lightweight():
    fullchain = [json.loads(block) for block in blockchain.chain]
    lightWeight = []
    for block in fullchain:
        blockObject = Block(block['index'], block['transactions'], block['timestamp'], block['previous_hash'],
                            block['difficulty'])
        blockObject.merkle_root = block['merkle_root']
        blockObject.nonce = block['nonce']
        blockObject.difficulty = block['difficulty']
        lightWeight.append(blockObject.to_dict())
    response = {
        'chain': json.dumps(lightWeight),
        'length': len(lightWeight)
    }
    return jsonify(response), 200

@app.route('/merkle_path', methods=['POST'])
def merkle_path():
    values = request.form
    required = ['sender', 'recipient', 'value']
    # Check that the required fields are in the POST data
    if not all(k in values for k in required):
        return 'Missing values', 400
    transaction = Transaction(values.get('sender'), values.get('recipient'), values.get('value'))
    path = blockchain.merkle_path(transaction)

    if len(path) > 0:
        root = path[-1]
        path = path[:-1]
    return jsonify(path), 200


@app.route('/sync_difficulty_info', methods=['GET'])
def sync_difficulty_info():
    res = blockchain.sync_difficulty_info(request.host)
    if res:
        response = {'message': 'difficulty_info sync'}
        return jsonify(response), 200
    else:
        response = {'message': 'failed to sync difficulty_info'}
        return jsonify(response), 406


@app.route('/difficulty_info', methods=['GET'])
def difficulty_info():
    response = blockchain.difficulty_info
    return jsonify(response), 200


@app.route('/clear_transacrions', methods=['PUT'])
def clear_transacrions():
    blockchain.unconfirmed_transactions = []
    response = {'message': True}
    return jsonify(response), 200


if __name__ == "__main__":
    myWallet = Wallet()
    blockchain = Blockchain()
    port = 5002
    app.run(host='127.0.0.1', port=port)