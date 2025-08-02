# app.py
import os
from flask import Flask, render_template, request, jsonify
from iso_client import send_iso_request, FIELD_39_RESPONSES # Import FIELD_39_RESPONSES for use in app.py if needed, or just keep in iso_client

# Initialize Flask application
app = Flask(__name__)

# --- Configuration ---
# Sensitive information like API keys or server addresses MUST be loaded from environment variables for security.
# For Render.com, you would set these as environment variables in your service settings.
# Refer to the .env.example file for a list of expected environment variables.

ISO_SERVER_HOST = os.environ.get('ISO_SERVER_HOST', '127.0.0.1') # Default for local testing; MUST be set on Render
ISO_SERVER_PORT = int(os.environ.get('ISO_SERVER_PORT', 12345)) # Default for local testing; MUST be set on Render

MERCHANT_WALLET_ADDRESS = os.environ.get('MERCHANT_WALLET_ADDRESS', '0xYourRealMerchantWalletAddressHere') # MUST be set on Render
WEB3_PROVIDER_URL = os.environ.get('WEB3_PROVIDER_URL', 'http://localhost:8545') # Default for local testing; MUST be set on Render
SENDER_WALLET_PRIVATE_KEY = os.environ.get('SENDER_WALLET_PRIVATE_KEY', '0xYourSendingWalletPrivateKeyHere') # MUST be set on Render (EXTREMELY SENSITIVE)
SENDER_WALLET_ADDRESS = os.environ.get('SENDER_WALLET_ADDRESS', '0xYourSendingWalletAddressHere') # MUST be set on Render

# --- Routes ---

@app.route('/')
def index():
    """
    Renders the main virtual POS terminal HTML page.
    """
    return render_template('index.html')

@app.route('/process_payment', methods=['POST'])
def process_payment():
    """
    API endpoint to process a payment request.
    It receives payment details, sends an ISO 8583 request,
    and if approved, triggers a crypto payout.
    """
    data = request.get_json()
    amount = data.get('amount')
    card_number = data.get('cardNumber')
    expiry_date = data.get('expiryDate')
    cvv = data.get('cvv')
    auth_code = data.get('authCode')
    protocol_name = data.get('protocol') # New: Get selected protocol

    if not all([amount, card_number, expiry_date, cvv, protocol_name]): # Auth code is optional, protocol is required
        return jsonify({"status": "error", "message": "Missing required payment details or protocol selection"}), 400

    app.logger.info(f"Received payment request: Amount={amount}, Card={card_number}, Exp={expiry_date}, CVV={cvv}, Auth={auth_code}, Protocol={protocol_name}")

    # Step 1: Send ISO 8583 Authorization Request to the Card Owner's ISO 8583 Server
    # Pass all collected card details and the selected protocol to the ISO client
    iso_response = send_iso_request(
        ISO_SERVER_HOST,
        ISO_SERVER_PORT,
        card_number,
        amount,
        expiry_date,
        cvv,
        auth_code,
        protocol_name # New: Pass protocol name
    )

    transaction_status = iso_response.get('status')
    iso_message = iso_response.get('message')
    crypto_payout_status = "N/A"
    crypto_payout_message = "No payout triggered"

    if transaction_status == "approved":
        app.logger.info("ISO 8583 transaction approved. Triggering crypto payout.")
        # Pass all necessary crypto configuration to the crypto module
        payout_result = trigger_crypto_payout(
            amount,
            "USDT",
            merchant_wallet_address=MERCHANT_WALLET_ADDRESS,
            web3_provider_url=WEB3_PROVIDER_URL,
            sender_private_key=SENDER_WALLET_PRIVATE_KEY,
            sender_address=SENDER_WALLET_ADDRESS
        )
        crypto_payout_status = payout_result.get('status')
        crypto_payout_message = payout_result.get('message')
        app.logger.info(f"Crypto payout status: {crypto_payout_status}, Message: {crypto_payout_message}")
    else:
        app.logger.warning(f"ISO 8583 transaction declined: {iso_message}")

    # Return the combined status to the frontend
    return jsonify({
        "transaction_status": transaction_status,
        "iso_message": iso_message,
        "crypto_payout_status": crypto_payout_status,
        "crypto_payout_message": crypto_payout_message
    })

# --- Main execution block ---
if __name__ == '__main__':
    # For local development, run with debug=True
    # For production on Render.com, Gunicorn will manage the application.
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
