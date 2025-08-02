# crypto.py
import os
import random # Kept for generating realistic-looking transaction IDs for the placeholder
import json # Needed for loading ABI from a file

# You will need to install web3.py:
# pip install web3

# Conceptual imports for a real blockchain interaction
from web3 import Web3

# Path to your USDT ABI file
USDT_ABI_PATH = "usdt_abi.json"
# Example ERC-20 USDT on Ethereum Mainnet. Adjust for your chain/token.
USDT_CONTRACT_ADDRESS = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

def trigger_crypto_payout(
    amount: float,
    currency: str,
    merchant_wallet_address: str,
    web3_provider_url: str,
    sender_private_key: str,
    sender_address: str
) -> dict:
    """
    Attempts to trigger a real crypto payout to the specified merchant wallet address.
    This function outlines the steps for a real crypto transaction using web3.py.
    """
    print(f"Crypto Payout: Attempting payout of {amount} {currency} to {merchant_wallet_address}...")

    if not merchant_wallet_address or not merchant_wallet_address.startswith('0x'):
        return {"status": "failed", "message": "Invalid merchant wallet address format."}
    if not web3_provider_url:
        return {"status": "failed", "message": "Missing WEB3_PROVIDER_URL."}
    if not sender_private_key:
        return {"status": "failed", "message": "Missing SENDER_WALLET_PRIVATE_KEY."}
    if not sender_address or not sender_address.startswith('0x'):
        return {"status": "failed", "message": "Invalid SENDER_WALLET_ADDRESS format."}

    try:
        # 1. Initialize Web3 Provider:
        w3 = Web3(Web3.HTTPProvider(web3_provider_url))

        # For Proof-of-Authority (PoA) chains (e.g., BSC, Polygon), add middleware:
        # Example: if w3.eth.chain_id == 56: # BSC Mainnet Chain ID
        #     w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        # 2. Check Connection:
        if not w3.is_connected():
            print("Crypto Payout: Not connected to blockchain provider.")
            return {"status": "failed", "message": "Blockchain connection failed. Check WEB3_PROVIDER_URL."}
        print(f"Crypto Payout: Connected to blockchain. Chain ID: {w3.eth.chain_id}")

        # 3. Load Token Contract ABI and Instance:
        try:
            with open(USDT_ABI_PATH, 'r') as f:
                usdt_abi = json.load(f)
        except FileNotFoundError:
            print(f"Error: USDT ABI file not found at {USDT_ABI_PATH}")
            return {"status": "failed", "message": "USDT ABI file missing."}

        usdt_contract = w3.eth.contract(address=Web3.to_checksum_address(USDT_CONTRACT_ADDRESS), abi=usdt_abi)

        # 4. Convert Fiat Amount to Token Units (considering token decimals):
        # USDT typically has 6 decimals. Verify for your specific token.
        usdt_decimals = usdt_contract.functions.decimals().call()
        amount_in_token_units = int(amount * (10 ** usdt_decimals))
        print(f"Crypto Payout: Converting {amount} USD to {amount_in_token_units} token units (with {usdt_decimals} decimals).")

        # 5. Build Transaction:
        # Ensure sender_address is checksummed
        sender_checksum_address = Web3.to_checksum_address(sender_address)
        merchant_checksum_address = Web3.to_checksum_address(merchant_wallet_address)

        nonce = w3.eth.get_transaction_count(sender_checksum_address)
        gas_price = w3.eth.gas_price # Use current network gas price
        gas_limit = 100000 # This is an estimate; use w3.eth.estimate_gas for more accuracy if needed

        transaction = usdt_contract.functions.transfer(
            merchant_checksum_address,
            amount_in_token_units
        ).build_transaction({
            'chainId': w3.eth.chain_id,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'nonce': nonce,
            'from': sender_checksum_address
        })
        print(f"Crypto Payout: Built transaction: {transaction}")

        # 6. Sign Transaction:
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key=sender_private_key)
        print("Crypto Payout: Transaction signed.")

        # 7. Send Transaction:
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        print(f"Crypto Payout: Transaction sent. Tx Hash: {tx_hash.hex()}")

        # 8. Wait for Transaction Confirmation (Highly recommended for production):
        # This will block until the transaction is mined or timeout occurs.
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300) # Wait up to 5 minutes
        print(f"Crypto Payout: Transaction receipt: {receipt}")

        if receipt.status == 1:
            print("Crypto Payout: Transaction confirmed successfully on blockchain.")
            return {"status": "success", "message": f"Crypto payout successful. Tx Hash: {tx_hash.hex()}"}
        else:
            print("Crypto Payout: Transaction failed on blockchain (receipt status 0).")
            return {"status": "failed", "message": "Blockchain transaction failed (receipt status 0)."}

    except Exception as e:
        print(f"Crypto Payout: An error occurred during payout: {e}")
        return {"status": "failed", "message": f"Crypto payout error: {e}. Check logs for details."}
