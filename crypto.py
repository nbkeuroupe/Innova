# iso_client.py
import socket
import struct # For packing/unpacking binary data (e.g., length prefixes, numeric fields)
import time   # Import the time module to use time.time()
import binascii # For converting between binary and ASCII hex (e.g., BCD)

# --- PROTOCOL DEFINITIONS ---
# These define the expected length of the authorization code based on the protocol.
# You can extend this to include other protocol-specific behaviors.
PROTOCOLS = {
    "POS Terminal -101.1 (4-digit approval)": {"auth_code_length": 4, "type": "approval"},
    "POS Terminal -101.4 (6-digit approval)": {"auth_code_length": 6, "type": "approval"},
    "POS Terminal -101.6 (Pre-authorization)": {"auth_code_length": 6, "type": "pre_auth"},
    "POS Terminal -101.7 (4-digit approval)": {"auth_code_length": 4, "type": "approval"},
    "POS Terminal -101.8 (PIN-LESS transaction)": {"auth_code_length": 4, "type": "pinless"},
    "POS Terminal -201.1 (6-digit approval)": {"auth_code_length": 6, "type": "approval"},
    "POS Terminal -201.3 (6-digit approval)": {"auth_code_length": 6, "type": "approval"},
    "POS Terminal -201.5 (6-digit approval)": {"auth_code_length": 6, "type": "approval"}
}

# --- FIELD 39 RESPONSE CODES ---
# These provide human-readable messages for specific ISO 8583 response codes.
FIELD_39_RESPONSES = {
    "00": "Approved - Transaction Successful", # Standard approval code
    "05": "Do Not Honor - Contact Card Issuer",
    "14": "Invalid Card Number or Format", # Often used for invalid PAN
    "54": "Expired Card",
    "82": "Invalid CVV",
    "91": "Issuer Inoperative - Try Again Later",
    "92": "Invalid Terminal Protocol - Configuration Error",
    # Add more ISO 8583 response codes and their meanings as per your server's documentation
}


# --- ISO 8583 Message Specification (CRITICAL: VERIFY AGAINST YOUR SERVER'S DOCS) ---
# This dictionary defines the properties of each Data Element (DE).
# You MUST adjust these values (length, encoding, type, length_prefix_bytes, max_length)
# to precisely match your Card Owner's ISO 8583 Server documentation.
#
# 'length': Fixed length in characters/digits for fixed-length fields.
# 'encoding': 'ascii', 'bcd', 'hex'. 'bcd' means Binary Coded Decimal.
# 'type':
#   'N' (Numeric, fixed length)
#   'AN' (Alphanumeric, fixed length)
#   'LLVAR_N' (Numeric, variable length, 1-byte length prefix, max 99 digits)
#   'LLVAR_AN' (Alphanumeric, variable length, 2-byte length prefix, max 99 chars)
#   'LLLVAR_B' (Binary, variable length, 3-byte length prefix, max 999 bytes)
# 'length_prefix_bytes': Number of ASCII characters/digits used for the length prefix (e.g., 2 for LLVAR_AN)
# 'max_length': Maximum data length for variable fields (excluding prefix).

ISO_MESSAGE_SPEC = {
    # MTI (Message Type Indicator) - 4 ASCII characters
    "MTI": {"length": 4, "encoding": "ascii", "type": "AN"},

    # Data Elements (DEs) - common definitions, adjust as needed
    "DE_2_PAN": {"length_prefix_bytes": 2, "max_length": 19, "encoding": "ascii", "type": "LLVAR_N"}, # Primary Account Number (up to 19 digits)
    "DE_3_PROCESSING_CODE": {"length": 6, "encoding": "ascii", "type": "N"}, # Processing Code (e.g., "000000" for purchase)
    "DE_4_AMOUNT": {"length": 12, "encoding": "ascii", "type": "N"}, # Amount, Transaction (e.g., "000000010500" for $10.50)
    "DE_7_TRANSMISSION_DATE_TIME": {"length": 10, "encoding": "ascii", "type": "N"}, # YYMMDDhhmmss
    "DE_11_STAN": {"length": 6, "encoding": "ascii", "type": "N"}, # System Trace Audit Number
    "DE_12_LOCAL_TRANSACTION_TIME": {"length": 6, "encoding": "ascii", "type": "N"}, # hhmmss
    "DE_13_LOCAL_TRANSACTION_DATE": {"length": 4, "encoding": "ascii", "type": "N"}, # MMYY
    "DE_14_EXPIRY_DATE": {"length": 4, "encoding": "ascii", "type": "N"}, # Expiration Date (YYMM)
    "DE_22_POS_ENTRY_MODE": {"length": 3, "encoding": "ascii", "type": "N"}, # Point of Service Entry Mode (e.g., "010" for manual)
    "DE_39_RESPONSE_CODE": {"length": 2, "encoding": "ascii", "type": "N"}, # Response Code (e.g., "00" for approved)
    "DE_41_TERMINAL_ID": {"length": 8, "encoding": "ascii", "type": "AN"}, # Card Acceptor Terminal ID
    "DE_42_MERCHANT_ID": {"length": 15, "encoding": "ascii", "type": "AN"}, # Card Acceptor ID Code
    "DE_49_CURRENCY_CODE": {"length": 3, "encoding": "ascii", "type": "N"}, # Currency Code, Transaction (e.g., "840" for USD)
    "DE_52_PIN_DATA": {"length": 8, "encoding": "hex", "type": "B"}, # Encrypted PIN Block (8 bytes, 16 hex chars)
    "DE_55_ICC_DATA": {"length_prefix_bytes": 3, "max_length": 255, "encoding": "ascii", "type": "LLLVAR_B"}, # Integrated Circuit Card (ICC) Data - for EMV
    "DE_60_PRIVATE_DATA": {"length_prefix_bytes": 2, "max_length": 99, "encoding": "ascii", "type": "LLVAR_AN"}, # Private Data (often used for CVV, Auth Code)
    "DE_61_ISSUER_PRIVATE_DATA": {"length_prefix_bytes": 2, "max_length": 99, "encoding": "ascii", "type": "LLVAR_AN"}, # Issuer Private Data
    "DE_62_ACQUIRER_PRIVATE_DATA": {"length_prefix_bytes": 2, "max_length": 99, "encoding": "ascii", "type": "LLVAR_AN"}, # Acquirer Private Data
    "DE_63_ADDITIONAL_PRIVATE_DATA": {"length_prefix_bytes": 2, "max_length": 99, "encoding": "ascii", "type": "LLVAR_AN"}, # Additional Private Data
}

# Define the order of DEs for a specific message type (e.g., 0100 Authorization Request)
# The order here MUST match the order implied by the bitmap and your server's spec.
# This list determines the sequence of packed DEs after the bitmap.
DE_ORDER_0100_REQUEST = [
    "DE_2_PAN",
    "DE_3_PROCESSING_CODE",
    "DE_4_AMOUNT",
    "DE_7_TRANSMISSION_DATE_TIME",
    "DE_11_STAN",
    "DE_12_LOCAL_TRANSACTION_TIME",
    "DE_13_LOCAL_TRANSACTION_DATE",
    "DE_14_EXPIRY_DATE",
    "DE_22_POS_ENTRY_MODE",
    "DE_41_TERMINAL_ID",
    "DE_42_MERCHANT_ID",
    "DE_49_CURRENCY_CODE",
    "DE_60_PRIVATE_DATA", # For CVV/Auth Code
    # Add other DEs as they appear in your message
]

# Define the order of DEs for a specific response type (e.g., 0110 Authorization Response)
# This list is used by the parsing logic to know what to expect and in what order.
DE_ORDER_0110_RESPONSE = [
    "DE_2_PAN", # Example: PAN might be echoed back
    "DE_3_PROCESSING_CODE",
    "DE_4_AMOUNT",
    "DE_7_TRANSMISSION_DATE_TIME",
    "DE_11_STAN",
    "DE_12_LOCAL_TRANSACTION_TIME",
    "DE_13_LOCAL_TRANSACTION_DATE",
    "DE_39_RESPONSE_CODE", # Response Code is crucial
    "DE_41_TERMINAL_ID",
    "DE_42_MERCHANT_ID",
    "DE_60_PRIVATE_DATA", # Example: server might return private data
    # Add other DEs as they appear in the response message
]


def generate_stan() -> str:
    """Generates a unique System Trace Audit Number (STAN)."""
    # In a real system, this should be persistent and incrementing for each transaction.
    # Using time.time() for a unique, but not necessarily sequential, STAN.
    # Ensures it's 6 digits, zero-padded.
    return str(int(time.time() * 1000000))[-6:].zfill(6)


def get_current_datetime_iso() -> str:
    """Generates DE 7 (Transmission Date and Time) in YYMMDDhhmmss format (10 chars)."""
    return time.strftime("%y%m%d%H%M%S", time.gmtime())

def get_current_local_time() -> str:
    """Generates DE 12 (Local Transaction Time) in hhmmss format (6 chars)."""
    return time.strftime("%H%M%S")

def get_current_local_date() -> str:
    """Generates DE 13 (Local Transaction Date) in MMYY format (4 chars)."""
    return time.strftime("%m%y")


def _ascii_to_bcd(s: str, pad_right: bool = True) -> bytes:
    """Converts an ASCII numeric string to BCD bytes."""
    if not s.isdigit():
        raise ValueError(f"Input for BCD conversion must be numeric: {s}")
    if len(s) % 2 != 0:
        s += '0' if pad_right else 'F' # Pad with '0' or 'F' (nibble for odd length)
    return binascii.unhexlify(s)

def _bcd_to_ascii(b: bytes) -> str:
    """Converts BCD bytes to an ASCII numeric string."""
    return binascii.hexlify(b).decode('ascii')


def pack_data_element(value, spec) -> bytes:
    """Packs a single data element according to its specification."""
    data_type = spec.get("type")
    encoding = spec.get("encoding", "ascii")
    length = spec.get("length")
    length_prefix_bytes = spec.get("length_prefix_bytes")

    packed_data = b''

    if data_type == "LLVAR_N": # Numeric, variable length, 1-byte BCD length prefix (0-99 digits)
        # Value must be digits only
        if not str(value).isdigit():
            raise ValueError(f"LLVAR_N value '{value}' must be numeric.")
        encoded_value = value.encode(encoding)
        if len(encoded_value) > spec["max_length"]:
            raise ValueError(f"Value '{value}' exceeds max length {spec['max_length']}")
        # Length prefix is 1 byte BCD representing length (e.g., length 12 -> b'\x12')
        packed_data += _ascii_to_bcd(str(len(encoded_value)).zfill(2), pad_right=False)[-length_prefix_bytes:]
        packed_data += encoded_value
    elif data_type == "N": # Fixed length Numeric
        if not str(value).isdigit():
            raise ValueError(f"Numeric value '{value}' must be digits only.")
        packed_data += str(value).zfill(length).encode(encoding)
    elif data_type == "AN": # Fixed length Alphanumeric
        packed_data += value.ljust(length).encode(encoding)
    elif data_type == "LLVAR_AN": # Alphanumeric, variable length, 2-byte ASCII length prefix (0-99 chars)
        encoded_value = value.encode(encoding)
        if len(encoded_value) > spec["max_length"]:
            raise ValueError(f"Value '{value}' exceeds max length {spec['max_length']}")
        # Length prefix is 2 ASCII digits (e.g., "12")
        packed_data += f"{len(encoded_value):0{length_prefix_bytes}d}".encode(encoding)
        packed_data += encoded_value
    elif data_type == "LLLVAR_B": # Binary, variable length, 3-byte ASCII length prefix (0-999 bytes)
        # Value is expected to be a hex string, convert to bytes
        binary_value = binascii.unhexlify(value)
        if len(binary_value) > spec["max_length"]:
            raise ValueError(f"Binary value '{value}' exceeds max length {spec['max_length']} bytes.")
        # Length prefix is 3 ASCII digits (e.g., "012")
        packed_data += f"{len(binary_value):0{length_prefix_bytes}d}".encode(encoding)
        packed_data += binary_value
    elif data_type == "B": # Fixed length Binary (hex string input)
        binary_value = binascii.unhexlify(value)
        if len(binary_value) != length:
            raise ValueError(f"Binary value '{value}' length mismatch. Expected {length} bytes, got {len(binary_value)}.")
        packed_data += binary_value
    else:
        raise ValueError(f"Unsupported data type: {data_type} for value: {value}")

    return packed_data


def unpack_data_element(data_bytes: bytes, offset: int, spec) -> tuple[any, int]:
    """Unpacks a single data element from bytes and returns its value and new offset."""
    data_type = spec.get("type")
    encoding = spec.get("encoding", "ascii")
    length = spec.get("length")
    length_prefix_bytes = spec.get("length_prefix_bytes")

    value = None
    read_bytes_count = 0

    if data_type == "LLVAR_N":
        # Read 1-byte BCD length prefix
        len_byte = data_bytes[offset : offset + length_prefix_bytes]
        actual_len = int(_bcd_to_ascii(len_byte))
        offset += length_prefix_bytes
        # Read actual data
        value = data_bytes[offset : offset + actual_len].decode(encoding)
        read_bytes_count = length_prefix_bytes + actual_len
    elif data_type == "LLVAR_AN":
        # Read 2-byte ASCII length prefix
        len_str = data_bytes[offset : offset + length_prefix_bytes].decode(encoding)
        actual_len = int(len_str)
        offset += length_prefix_bytes
        # Read actual data
        value = data_bytes[offset : offset + actual_len].decode(encoding)
        read_bytes_count = length_prefix_bytes + actual_len
    elif data_type == "N" or data_type == "AN":
        value = data_bytes[offset : offset + length].decode(encoding)
        read_bytes_count = length
    elif data_type == "LLLVAR_B":
        # Read 3-byte ASCII length prefix
        len_str = data_bytes[offset : offset + length_prefix_bytes].decode(encoding)
        actual_len = int(len_str)
        offset += length_prefix_bytes
        # Read actual binary data and convert to hex string
        value = binascii.hexlify(data_bytes[offset : offset + actual_len]).decode('ascii') # Always hex for binary
        read_bytes_count = length_prefix_bytes + actual_len
    elif data_type == "B": # Fixed length Binary (output as hex string)
        value = binascii.hexlify(data_bytes[offset : offset + length]).decode('ascii')
        read_bytes_count = length
    else:
        raise ValueError(f"Unsupported data type for unpacking: {data_type}")

    return value, offset + read_bytes_count


def _generate_bitmap(de_data: dict) -> bytearray:
    """
    Generates an 8-byte primary bitmap based on the presence of DEs in de_data.
    Assumes DE numbers 1-64 for primary bitmap.
    """
    bitmap = bytearray(8) # Initialize with 8 zero bytes

    for de_name in de_data:
        # Extract DE number from name (e.g., "DE_2_PAN" -> 2)
        try:
            de_number = int(de_name.split('_')[1])
            if not (1 <= de_number <= 64):
                continue # Only handle primary bitmap DEs here
        except (ValueError, IndexError):
            continue # Skip if not a standard DE name format

        # Set the corresponding bit in the bitmap
        # ISO 8583 bits are 1-indexed. Bit 1 is most significant bit of first byte.
        # Python bytearray bits are 0-indexed from left (MSB).
        byte_index = (de_number - 1) // 8
        bit_position_in_byte = 7 - ((de_number - 1) % 8) # 0 is MSB, 7 is LSB

        if byte_index < 8: # Ensure we don't go out of bounds for 8-byte bitmap
            bitmap[byte_index] |= (1 << bit_position_in_byte)
    return bitmap


def build_iso_message(card_number: str, amount: float, expiry_date: str, cvv: str, auth_code: str, protocol_name: str) -> bytes:
    """
    Constructs a real ISO 8583 authorization request message in binary format.
    This function incorporates logic based on the selected protocol.
    YOU MUST CUSTOMIZE THIS BASED ON YOUR SERVER'S EXACT ISO 8583 SPECIFICATION.
    """
    mti = "0100" # Authorization Request MTI
    stan = generate_stan()
    amount_in_cents = str(int(amount * 100)).zfill(12) # Amount is typically 12 digits, in cents

    # Format expiry date to YYMM as per ISO 8583 DE 14
    # Assuming MM/YY input, converting to YYMM for DE 14
    mm, yy = expiry_date.split('/')
    formatted_expiry_yymm = yy + mm # Example: "2512" for 12/25

    # Get current time for DE 7, DE 12, DE 13
    transmission_datetime = get_current_datetime_iso() # YYMMDDhhmmss
    local_transaction_time = get_current_local_time() # hhmmss
    local_transaction_date = get_current_local_date() # MMYY

    # --- Prepare Data Elements for Packing ---
    # This dictionary holds the actual values for the DEs we intend to send.
    # Only include DEs that have a value.
    de_values_to_pack = {
        "DE_2_PAN": card_number,
        "DE_3_PROCESSING_CODE": "000000", # Purchase transaction. Adjust based on protocol if needed.
        "DE_4_AMOUNT": amount_in_cents,
        "DE_7_TRANSMISSION_DATE_TIME": transmission_datetime,
        "DE_11_STAN": stan,
        "DE_12_LOCAL_TRANSACTION_TIME": local_transaction_time,
        "DE_13_LOCAL_TRANSACTION_DATE": local_transaction_date,
        "DE_14_EXPIRY_DATE": formatted_expiry_yymm,
        "DE_22_POS_ENTRY_MODE": "010", # Manual entry. Adjust based on protocol if needed (e.g., for PIN-LESS).
        "DE_41_TERMINAL_ID": "VIRTUALP", # Your terminal ID
        "DE_42_MERCHANT_ID": "YOURMERCHANTID", # Your merchant ID
        "DE_49_CURRENCY_CODE": "840", # USD
    }

    # --- Protocol-specific handling for Auth Code and DE 60 ---
    protocol_info = PROTOCOLS.get(protocol_name)
    if not protocol_info:
        raise ValueError(f"Invalid protocol name: {protocol_name}")

    if protocol_info["type"] == "approval" or protocol_info["type"] == "pinless":
        # For approval/pinless, auth_code is typically sent in DE 60 or similar private field.
        # Ensure auth_code matches expected length for the selected protocol.
        if auth_code and len(auth_code) != protocol_info["auth_code_length"]:
            raise ValueError(f"Auth Code length mismatch for protocol '{protocol_name}'. Expected {protocol_info['auth_code_length']} digits, got {len(auth_code)}.")
        
        private_data_content = f"CVV:{cvv}"
        if auth_code:
            private_data_content += f";AUTH:{auth_code}"
        de_values_to_pack["DE_60_PRIVATE_DATA"] = private_data_content
    elif protocol_info["type"] == "pre_auth":
        # For pre-authorization, auth_code might be different or not sent in DE 60.
        # This is where you'd implement specific logic for pre-auth messages.
        # For now, we'll still include DE 60 with CVV, but auth_code handling might differ.
        private_data_content = f"CVV:{cvv}"
        if auth_code: # Still include if provided, but its meaning might change for pre-auth
            private_data_content += f";PREAUTH_CODE:{auth_code}"
        de_values_to_pack["DE_60_PRIVATE_DATA"] = private_data_content
        # You might also change MTI or DE 3 for pre-authorization if your server requires it.
        # mti = "0100" # Or "0100" with specific processing code for pre-auth
        # de_values_to_pack["DE_3_PROCESSING_CODE"] = "000000" # Example: "001000" for pre-auth

    # --- Constructing the Bitmap ---
    # Dynamically generate the primary bitmap based on the DEs we are sending.
    primary_bitmap = _generate_bitmap(de_values_to_pack)

    # --- Packing Data Elements ---
    # Pack DEs in the defined order (DE_ORDER_0100_REQUEST).
    # Only pack if the DE is present in de_values_to_pack.
    packed_elements = []
    for de_name in DE_ORDER_0100_REQUEST:
        if de_name in de_values_to_pack:
            spec = ISO_MESSAGE_SPEC.get(de_name)
            if not spec:
                raise ValueError(f"Specification for {de_name} not found in ISO_MESSAGE_SPEC.")
            packed_elements.append(pack_data_element(de_values_to_pack[de_name], spec))
        else:
            # If a DE is in the order list but no value is provided, it means it's optional
            # or not applicable for this transaction/protocol. Log for debugging.
            print(f"Info: Data Element '{de_name}' is in DE_ORDER_0100_REQUEST but no value provided to pack. Skipping.")


    # Assemble the full message (without length prefix yet)
    raw_message_bytes = mti.encode(ISO_MESSAGE_SPEC["MTI"]["encoding"]) + \
                        bytes(primary_bitmap) + \
                        b''.join(packed_elements)

    # --- Add Length Prefix (REQUIRED by most ISO 8583 servers) ---
    # Check your server's documentation for this. Common formats:
    # - 2-byte binary length (e.g., struct.pack('>H', len(raw_message_bytes)))
    # - 4-byte ASCII length (e.g., f"{len(raw_message_bytes):04d}".encode('ascii'))
    message_length = len(raw_message_bytes)
    # Assuming 2-byte big-endian binary length prefix (most common for TCP ISO 8583)
    length_prefix = struct.pack('>H', message_length) # '>H' for unsigned short, big-endian

    final_message = length_prefix + raw_message_bytes
    return final_message


def parse_iso_response(response_data: bytes) -> dict:
    """
    Parses an ISO 8583 response message from binary format.
    Uses FIELD_39_RESPONSES for descriptive messages.
    YOU MUST CUSTOMIZE THIS BASED ON YOUR SERVER'S EXACT ISO 8583 RESPONSE SPECIFICATION.
    """
    if not response_data:
        return {"status": "error", "message": "Empty response from ISO server."}

    offset = 0
    # --- Parse Length Prefix (if present in response) ---
    # Assuming 2-byte big-endian binary length prefix. Adjust if your server uses ASCII length.
    try:
        if len(response_data) < 2:
            print("ISO Client: Response too short to contain length prefix.")
            return {"status": "error", "message": "Incomplete ISO response (too short for length prefix)."}

        response_message_length = struct.unpack('>H', response_data[offset:offset+2])[0]
        offset += 2
        # Ensure we have enough data after parsing length
        if len(response_data) - offset < response_message_length:
            print(f"ISO Client: Incomplete response. Expected {response_message_length} bytes, got {len(response_data) - offset}.")
            return {"status": "error", "message": "Incomplete ISO response received."}
        # Slice the actual ISO message part
        actual_iso_message_bytes = response_data[offset : offset + response_message_length]
        offset = 0 # Reset offset for parsing the actual message
    except struct.error as e:
        print(f"ISO Client: Error unpacking length prefix (might not be present or malformed): {e}. Attempting to parse raw bytes as message.")
        actual_iso_message_bytes = response_data # Fallback if no length prefix
        offset = 0
    except Exception as e:
        print(f"ISO Client: Unexpected error parsing response length prefix: {e}")
        return {"status": "error", "message": "Error parsing ISO response length."}

    parsed_de_values = {}
    try:
        # --- Parse MTI ---
        mti_spec = ISO_MESSAGE_SPEC["MTI"]
        response_mti = actual_iso_message_bytes[offset : offset + mti_spec["length"]].decode(mti_spec["encoding"])
        offset += mti_spec["length"]
        parsed_de_values["MTI"] = response_mti

        # --- Parse Primary Bitmap ---
        if len(actual_iso_message_bytes) < offset + 8:
            raise IndexError("Response too short to contain primary bitmap.")
        primary_bitmap_bytes = actual_iso_message_bytes[offset : offset + 8]
        offset += 8
        # Convert bitmap bytes to an integer for easy bit checking
        primary_bitmap_int = int(binascii.hexlify(primary_bitmap_bytes), 16)
        parsed_de_values["Primary_Bitmap"] = primary_bitmap_bytes.hex()

        # --- Parse Data Elements based on Bitmap and Order ---
        # Iterate through DEs from 1 to 64 (for primary bitmap)
        for de_number in range(1, 65):
            # Check if the bit for this DE is set in the bitmap
            if (primary_bitmap_int >> (64 - de_number)) & 1:
                de_name = None
                # Find the DE name from our spec based on its number
                for key, val_spec in ISO_MESSAGE_SPEC.items():
                    if key.startswith(f"DE_{de_number}_"):
                        de_name = key
                        break
                
                if de_name and de_name in DE_ORDER_0110_RESPONSE: # Only unpack if it's in our expected response order
                    spec = ISO_MESSAGE_SPEC[de_name]
                    if len(actual_iso_message_bytes) <= offset:
                        print(f"Warning: Incomplete response for DE {de_name} at offset {offset}. Remaining bytes: {len(actual_iso_message_bytes) - offset}")
                        break # Stop parsing if no more data
                    
                    value, new_offset = unpack_data_element(actual_iso_message_bytes, offset, spec)
                    parsed_de_values[de_name] = value
                    offset = new_offset
                elif de_name:
                    # DE is present in bitmap but not in our expected response order or spec.
                    # In a real system, you'd need to know its length to skip it correctly.
                    # For simplicity, we'll just log and continue.
                    spec = ISO_MESSAGE_SPEC.get(de_name)
                    if spec and spec.get('length'):
                        skip_bytes = spec['length']
                        if spec.get('type', '').startswith('LLVAR'):
                             skip_bytes += spec.get('length_prefix_bytes', 0)
                        elif spec.get('type', '').startswith('LLLVAR'):
                             skip_bytes += spec.get('length_prefix_bytes', 0)
                        print(f"Info: DE {de_name} (bit {de_number}) present in bitmap but no spec or fixed length to skip. Skipping {skip_bytes} bytes.")
                        offset += skip_bytes
                    else:
                        print(f"Warning: DE {de_name} (bit {de_number}) present in bitmap, but no spec or fixed length to skip. Potential parsing issue.")
                        # This is a critical point; if you can't determine length, parsing will fail.
                        # For now, we'll break to prevent further errors.
                        break


        response_code = parsed_de_values.get("DE_39_RESPONSE_CODE")
        
        # Get descriptive message from FIELD_39_RESPONSES
        descriptive_message = FIELD_39_RESPONSES.get(response_code, f"Unknown Response Code: {response_code or 'N/A'}")

        if response_mti == "0110" and response_code == "00":
            return {"status": "approved", "message": descriptive_message}
        else:
            return {"status": "declined", "message": descriptive_message}

    except IndexError as e:
        print(f"Error: Not enough data to parse ISO response at critical point: {e}. Raw: {response_data.hex()}")
        return {"status": "error", "message": "Incomplete or malformed ISO response."}
    except ValueError as e:
        print(f"Error: Data packing/unpacking error during ISO response parsing: {e}. Raw: {response_data.hex()}")
        return {"status": "error", "message": f"ISO response data error: {e}"}
    except Exception as e:
        print(f"An unexpected error occurred during ISO response parsing: {e}. Raw response: {response_data.hex()}")
        return {"status": "error", "message": f"ISO response parsing error: {e}"}


def send_iso_request(host: str, port: int, card_number: str, amount: float, expiry_date: str, cvv: str, auth_code: str, protocol_name: str) -> dict:
    """
    Attempts to send an ISO 8583 authorization request to the specified server via socket.
    Includes expiry_date, cvv, auth_code, and selected protocol.
    """
    try:
        iso_message_bytes = build_iso_message(card_number, amount, expiry_date, cvv, auth_code, protocol_name)
    except ValueError as e:
        print(f"ISO Client: Error building ISO message: {e}")
        return {"status": "error", "message": f"Failed to build ISO message: {e}"}

    print(f"ISO Client: Attempting to send ISO 8583 request to {host}:{port}...")

    try:
        # Create a socket connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(15) # Increased timeout for network latency
            sock.connect((host, port))
            print(f"ISO Client: Connected to {host}:{port}")

            # Send the message
            sock.sendall(iso_message_bytes)
            print(f"ISO Client: Sent message (hex): {iso_message_bytes.hex()}")

            # Receive the response
            # ISO 8583 responses can vary in size; ensure buffer is large enough
            response_data = sock.recv(2048) # Increased buffer size
            print(f"ISO Client: Received raw response (hex): {response_data.hex()}")

            return parse_iso_response(response_data)

    except socket.timeout:
        print("ISO Client: Connection or read timed out.")
        return {"status": "error", "message": "ISO Server connection timed out."}
    except ConnectionRefusedError:
        print("ISO Client: Connection refused. Is the ISO server running and accessible from Render.com?")
        return {"status": "error", "message": "ISO Server connection refused. Check host/port and server status."}
    except Exception as e:
        print(f"ISO Client: An unexpected error occurred: {e}")
        return {"status": "error", "message": f"ISO Client error: {e}. Check network and server logs."}
