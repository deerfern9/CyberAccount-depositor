import requests
from web3 import Web3
from datetime import datetime
from eth_account.messages import encode_defunct

use_proxy = int(input('Use proxy? 0/1: '))
dep_amount = int(input('0. 2 MATIC\n1. Custom amount\nEnter amount id: '))
amoumt = 0
if dep_amount == 1:
    amount = input('Enter amount: ')

web3 = Web3(Web3.HTTPProvider("https://polygon.blockpi.network/v1/rpc/7433894eead0d1c58dbc40da4635dd42fd6cd8cb"))

cyber_contract_address = web3.to_checksum_address('0xcd97405Fb58e94954E825E46dB192b916A45d412')
cyber_contract_abi = '[{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"from","type":"address"},{"indexed":false,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Deposit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"user","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Withdraw","type":"event"},{"inputs":[{"internalType":"address","name":"to","type":"address"}],"name":"depositTo","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"deposits","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}]'
cyber_contract = web3.eth.contract(address=cyber_contract_address, abi=cyber_contract_abi)

headers = {
    'authority': 'api.cyberconnect.dev',
    'accept': '*/*',
    'authorization': '',
    'content-type': 'application/json',
    'origin': 'https://cyber.co',
    'referer': 'https://cyber.co/',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
}


def read_file(filename):
    result = []
    with open(filename, 'r') as file:
        for tmp in file.readlines():
            result.append(tmp.replace('\n', ''))

    return result


def write_to_file(filename, text):
    with open(filename, 'a') as file:
        file.write(f'{text}\n')


def get_nonce(address, proxy):
    json_data = {
        'query': '\n    mutation nonce($address: EVMAddress!) {\n  nonce(request: {address: $address}) {\n    status\n    message\n    data\n  }\n}\n    ',
        'variables': {
            'address': address,
        },
        'operationName': 'nonce',
    }

    response = requests.post('https://api.cyberconnect.dev/profile/', headers=headers, json=json_data, proxies=proxy)
    nonce = response.json()['data']['nonce']['data']
    return nonce


def sign_signature(private_key, message):
    message_hash = encode_defunct(text=message)
    signed_message = web3.eth.account.sign_message(message_hash, private_key)

    signature = signed_message.signature.hex()
    return signature


def get_authorization(address, signature, signed_message, proxy):
    json_data = {
        'query': '\n    mutation login($request: LoginRequest!) {\n  login(request: $request) {\n    status\n    message\n    data {\n      id\n      privateInfo {\n        accessToken\n      }\n    }\n  }\n}\n    ',
        'variables': {
            'request': {
                'address': address,
                'signature': signature,
                'signedMessage': signed_message,
            },
        },
        'operationName': 'login',
    }

    response = requests.post(
        'https://api.cyberconnect.dev/profile/',
        headers=headers,
        json=json_data,
        proxies=proxy,
    ).json()['data']['login']

    if response['status'] == "SUCCESS":
        authorization = response['data']['privateInfo']['accessToken']
        return authorization
    else:
        print(f'{response}')


def get_cyber_address(authorization, proxy):
    private_headers = headers.copy()
    private_headers['authorization'] = authorization

    json_data = {
        'query': '\n    query me {\n  me {\n    status\n    message\n    data {\n      ccProfiles {\n        handle\n      }\n      lightInfo {\n        avatar\n        formattedAddress\n        displayName\n      }\n      privateInfo {\n        accessToken\n        address\n      }\n      v3Info {\n        cyberAccount\n        totalPoints\n      }\n    }\n  }\n}\n    ',
        'operationName': 'me',
    }

    response = requests.post(
        'https://api.cyberconnect.dev/profile/',
        headers=private_headers,
        json=json_data,
        proxies=proxy
    ).json()['data']['me']
    if response['status'] == 'SUCCESS':
        cyber_address = response['data']['v3Info']['cyberAccount']
        return cyber_address
    else:
        print(response)


def deposit(private, address, cyber_address):
    try:
        tx = cyber_contract.functions.depositTo(cyber_address).build_transaction(
            {
                'from': address,
                'nonce': web3.eth.get_transaction_count(address),
                'value': [web3.to_wei(2, 'ether'), web3.to_wei(amount, 'ether')][dep_amount],
                'gasPrice': web3.eth.gas_price,
            }
        )

        tx_create = web3.eth.account.sign_transaction(tx, private)
        tx_hash = web3.eth.send_raw_transaction(tx_create.rawTransaction)
        write_to_file('hashes.txt', tx_hash.hex())
        print(f"{datetime.now().strftime('%d %H:%M:%S')} | {address} | Transaction hash: {tx_hash.hex()}")
    except Exception as e:
        print(f"{datetime.now().strftime('%d %H:%M:%S')} | {address} | ERROR: {e}")


def main(private, proxy):
    address = web3.eth.account.from_key(private).address
    proxy = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    nonce = get_nonce(address, proxy)
    msg = f'cyber.co wants you to sign in with your Ethereum account:\n{address}\n\n\nURI: https://cyber.co\nVersion: 1\nChain ID: 56\nNonce: {nonce}\nIssued At: 2023-08-04T10:57:32.803Z\nExpiration Time: 2023-08-18T10:57:32.803Z\nNot Before: 2023-08-04T10:57:32.803Z'
    signed_msg = sign_signature(private, msg)
    authorization = get_authorization(address, signed_msg, msg, proxy)
    cyber_address = get_cyber_address(authorization, proxy)
    deposit(private, address, cyber_address)


if __name__ == '__main__':
    privates = read_file('privates.txt')
    if use_proxy:
        proxies = read_file('proxies.txt')
    else:
        proxies = [None] * len(privates)

    for private, proxy in zip(privates, proxies):
        main(private, proxy)
