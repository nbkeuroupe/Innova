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
```html
<!-- templates/index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextGen POS Terminal</title>
    <!-- Tailwind CSS CDN -->
    <script src="[https://cdn.tailwindcss.com](https://cdn.tailwindcss.com)"></script>
    <!-- Google Fonts: Inter -->
    <link href="[https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap](https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap)" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            /* Dark Red and Black Gradient Background */
            background: linear-gradient(to bottom right, #1a1a1a, #000000, #8B0000); /* Dark Gray, Black, Dark Red */
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 1.5rem; /* Add some padding for smaller screens */
        }
        .pos-container {
            background-color: rgba(255, 255, 255, 0.05); /* Slightly transparent white for frosted effect */
            border-radius: 2rem; /* Even more rounded corners */
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5); /* Stronger, darker shadow */
            padding: 3rem 2.5rem; /* More generous padding */
            width: 100%;
            max-width: 520px; /* Slightly wider */
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1); /* Subtle white border */
            backdrop-filter: blur(15px); /* Stronger frosted glass effect */
            -webkit-backdrop-filter: blur(15px); /* For Safari */
            color: #e0e0e0; /* Lighter text for dark background */
        }
        .input-group {
            margin-bottom: 1.5rem;
            text-align: left;
        }
        .input-label {
            display: block;
            color: #a0a0a0; /* Lighter gray for labels */
            font-size: 0.9rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        .input-field {
            width: 100%;
            padding: 0.9rem 1.25rem;
            border: 1px solid #444444; /* Darker border */
            border-radius: 0.75rem; /* More rounded inputs */
            font-size: 1.05rem;
            color: #e0e0e0; /* Lighter text for inputs */
            background-color: #2a2a2a; /* Dark background for inputs */
            outline: none;
            transition: all 0.3s ease;
            box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.2);
        }
        .input-field:focus {
            border-color: #B22222; /* Firebrick for focus */
            box-shadow: 0 0 0 4px rgba(178, 34, 34, 0.4); /* Dark red focus ring */
            background-color: #3a3a3a; /* Slightly lighter dark background on focus */
        }
        .process-button {
            /* Dark Red and Black Gradient Button */
            background-image: linear-gradient(to right, #8B0000, #B22222); /* Dark Red to Firebrick */
            color: white;
            padding: 1rem 2rem;
            border-radius: 1rem; /* Very rounded button */
            font-size: 1.2rem;
            font-weight: 700; /* Bolder text */
            cursor: pointer;
            transition: all 0.3s ease-in-out;
            border: none;
            width: 100%;
            box-shadow: 0 8px 25px rgba(139, 0, 0, 0.4); /* Deeper shadow matching button */
            letter-spacing: 0.05em; /* Slightly spaced letters */
        }
        .process-button:hover {
            transform: translateY(-3px) scale(1.01); /* More pronounced lift */
            box-shadow: 0 12px 35px rgba(139, 0, 0, 0.6);
            background-image: linear-gradient(to right, #6A0000, #8B0000); /* Darker on hover */
        }
        .process-button:active {
            transform: translateY(0);
            box-shadow: 0 4px 15px rgba(139, 0, 0, 0.2);
        }
        .status-message {
            margin-top: 2rem;
            padding: 1.25rem;
            border-radius: 1rem;
            font-weight: 600;
            text-align: left;
            border: 1px solid;
            display: none; /* Hidden by default */
            line-height: 1.6;
            font-size: 0.95rem;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2); /* Darker shadow for status messages */
        }
        .status-message.success {
            background-color: #1c332c; /* Darker green background */
            color: #4CAF50; /* Brighter green text */
            border-color: #2E8B57; /* SeaGreen border */
        }
        .status-message.error {
            background-color: #3b1e1e; /* Darker red background */
            color: #F44336; /* Brighter red text */
            border-color: #B22222; /* Firebrick border */
        }
        .status-message.info {
            background-color: #1e2a3b; /* Darker blue background */
            color: #2196F3; /* Brighter blue text */
            border-color: #1976D2; /* Darker blue border */
        }
        .loading-spinner {
            border: 4px solid #444444; /* Darker spinner base */
            border-top: 4px solid #B22222; /* Dark red spinner top */
            border-radius: 50%;
            width: 28px; /* Slightly larger spinner */
            height: 28px;
            animation: spin 1s linear infinite;
            display: inline-block;
            vertical-align: middle;
            margin-right: 0.75rem;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        /* Responsive adjustments */
        @media (max-width: 640px) {
            .pos-container {
                padding: 2rem 1.5rem;
                border-radius: 1.5rem;
            }
            .process-button {
                font-size: 1.1rem;
                padding: 0.9rem 1.5rem;
            }
            .input-field {
                font-size: 1rem;
                padding: 0.8rem 1rem;
            }
        }
    </style>
</head>
<body class="antialiased">
    <div class="pos-container">
        <h2 class="text-4xl font-extrabold text-white mb-4 tracking-tight">Virtual POS Terminal</h2>
        <p class="text-gray-300 text-lg mb-8 leading-relaxed">Securely process M0/M1 card payments and trigger crypto payouts.</p>

        <div class="input-group">
            <label for="protocolSelect" class="input-label">Select Protocol</label>
            <select id="protocolSelect" class="input-field" required>
                <option value="">-- Choose Protocol --</option>
                <option value="POS Terminal -101.1 (4-digit approval)">POS Terminal -101.1 (4-digit approval)</option>
                <option value="POS Terminal -101.4 (6-digit approval)">POS Terminal -101.4 (6-digit approval)</option>
                <option value="POS Terminal -101.6 (Pre-authorization)">POS Terminal -101.6 (Pre-authorization)</option>
                <option value="POS Terminal -101.7 (4-digit approval)">POS Terminal -101.7 (4-digit approval)</option>
                <option value="POS Terminal -101.8 (PIN-LESS transaction)">POS Terminal -101.8 (PIN-LESS transaction)</option>
                <option value="POS Terminal -201.1 (6-digit approval)">POS Terminal -201.1 (6-digit approval)</option>
                <option value="POS Terminal -201.3 (6-digit approval)">POS Terminal -201.3 (6-digit approval)</option>
                <option value="POS Terminal -201.5 (6-digit approval)">POS Terminal -201.5 (6-digit approval)</option>
            </select>
        </div>

        <div class="input-group">
            <label for="amount" class="input-label">Amount (USD)</label>
            <input type="number" id="amount" class="input-field" placeholder="e.g., 10.50" step="0.01" required>
        </div>

        <div class="input-group">
            <label for="cardNumber" class="input-label">M0/M1 Card Number</label>
            <input type="text" id="cardNumber" class="input-field" placeholder="e.g., 4111 2222 3333 4444" required maxlength="19">
        </div>

        <div class="grid grid-cols-2 gap-4 mb-1.5">
            <div class="input-group !mb-0">
                <label for="expiryDate" class="input-label">MM/YY</label>
                <input type="text" id="expiryDate" class="input-field" placeholder="MM/YY" required maxlength="5">
            </div>
            <div class="input-group !mb-0">
                <label for="cvv" class="input-label">CVV</label>
                <input type="text" id="cvv" class="input-field" placeholder="CVV" required maxlength="4">
            </div>
        </div>

        <div class="input-group">
            <label for="authCode" class="input-label">Authorization Code (if applicable)</label>
            <input type="text" id="authCode" class="input-field" placeholder="e.g., 123456" maxlength="6">
        </div>

        <button id="processPaymentBtn" class="process-button">Process Payment</button>

        <div id="statusMessage" class="status-message">
            <p id="transactionStatus" class="font-bold text-white"></p>
            <p id="payoutStatus" class="mt-2 text-gray-200"></p>
        </div>
    </div>

    <script>
        const processPaymentBtn = document.getElementById('processPaymentBtn');
        const protocolSelect = document.getElementById('protocolSelect'); // New
        const amountInput = document.getElementById('amount');
        const cardNumberInput = document.getElementById('cardNumber');
        const expiryDateInput = document.getElementById('expiryDate');
        const cvvInput = document.getElementById('cvv');
        const authCodeInput = document.getElementById('authCode');
        const statusMessageDiv = document.getElementById('statusMessage');
        const transactionStatusP = document.getElementById('transactionStatus');
        const payoutStatusP = document.getElementById('payoutStatus');

        // --- Input Formatting Logic ---

        // Card Number Formatting
        cardNumberInput.addEventListener('input', (e) => {
            const { value } = e.target;
            // Remove all non-digit characters
            let cleanedValue = value.replace(/\D/g, '');
            // Add space every 4 digits
            let formattedValue = cleanedValue.replace(/(\d{4})(?=\d)/g, '$1 ');
            e.target.value = formattedValue;
        });

        // Expiry Date (MM/YY) Formatting
        expiryDateInput.addEventListener('input', (e) => {
            let { value } = e.target;
            // Remove all non-digit characters
            let cleanedValue = value.replace(/\D/g, '');

            if (cleanedValue.length > 2) {
                // Add '/' after 2 digits (MM)
                value = cleanedValue.substring(0, 2) + '/' + cleanedValue.substring(2, 4);
            } else {
                value = cleanedValue;
            }
            e.target.value = value;
        });


        processPaymentBtn.addEventListener('click', async () => {
            const protocol = protocolSelect.value; // New: Get selected protocol
            const amount = parseFloat(amountInput.value);
            // Clean card number by removing spaces before sending
            const cardNumber = cardNumberInput.value.replace(/\s/g, '');
            const expiryDate = expiryDateInput.value.trim();
            const cvv = cvvInput.value.trim();
            const authCode = authCodeInput.value.trim();

            // Basic client-side validation
            if (!protocol) {
                displayMessage("Please select a protocol.", "error");
                return;
            }
            if (isNaN(amount) || amount <= 0) {
                displayMessage("Please enter a valid amount.", "error");
                return;
            }
            if (!cardNumber) {
                displayMessage("Please enter a card number.", "error");
                return;
            }
            if (!expiryDate || !/^(0[1-9]|1[0-2])\/\d{2}$/.test(expiryDate)) { // Basic MM/YY format check
                displayMessage("Please enter a valid MM/YY (e.g., 12/25).", "error");
                return;
            }
            if (!cvv || !/^\d{3,4}$/.test(cvv)) { // Basic 3 or 4 digit CVV check
                displayMessage("Please enter a valid 3 or 4 digit CVV.", "error");
                return;
            }
            // Auth code is optional, so no strict validation here

            // Clear previous messages and show loading
            displayMessage("Processing payment...", "info", true);
            processPaymentBtn.disabled = true;
            processPaymentBtn.innerHTML = '<span class="loading-spinner"></span> Processing...';

            try {
                const response = await fetch(`${window.location.origin}/process_payment`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        amount,
                        cardNumber,
                        expiryDate,
                        cvv,
                        authCode,
                        protocol // New: Send protocol
                    }),
                });

                const result = await response.json();

                if (response.ok) {
                    let msg = `Transaction: ${result.transaction_status.toUpperCase()} - ${result.iso_message}`;
                    let type = result.transaction_status === 'approved' ? 'success' : 'error';
                    displayMessage(msg, type);

                    if (result.transaction_status === 'approved') {
                        let payoutMsg = `Payout: ${result.crypto_payout_status.toUpperCase()} - ${result.crypto_payout_message}`;
                        let payoutType = result.crypto_payout_status === 'success' ? 'success' : 'error';
                        displayMessage(payoutMsg, payoutType, false, true); // Append payout status
                    }
                } else {
                    displayMessage(`Error: ${result.message || 'Something went wrong.'}`, "error");
                }
            } catch (error) {
                console.error('Fetch error:', error);
                displayMessage('Network error or server unreachable. Please try again.', "error");
            } finally {
                processPaymentBtn.disabled = false;
                processPaymentBtn.innerHTML = 'Process Payment';
            }
        });

        function displayMessage(message, type, clear = true, append = false) {
            if (clear) {
                transactionStatusP.textContent = '';
                payoutStatusP.textContent = '';
                statusMessageDiv.className = 'status-message'; // Reset classes
            }

            if (append) {
                payoutStatusP.textContent = message;
            } else {
                transactionStatusP.textContent = message;
            }

            statusMessageDiv.classList.add(type);
            statusMessageDiv.style.display = 'block';
        }
    </script>
</body>
</html>
```python
# crypto.py
import os
import random # Kept for generating realistic-looking transaction IDs for the placeholder
import json # Needed for loading ABI from a file

# You will need to install web3.py:
# pip install web3

# Conceptual imports for a real blockchain interaction
from web3 import Web3
from web3.middleware.geth_poa import geth_poa_middleware # Corrected import path

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
```text
# requirements.txt
Flask==2.3.2
gunicorn==21.2.0
web3==6.11.1
```text
# Procfile
web: gunicorn --bind 0.0.0.0:$PORT app:app
```dockerfile
# Dockerfile
# Use an official Python runtime as a parent image
FROM python:3.9-slim-buster

# Set the working directory in the container
WORKDIR /app

# Install any needed packages specified in requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Expose the port the app runs on
EXPOSE $PORT

# Run the application using Gunicorn
CMD exec gunicorn --bind 0.0.0.0:$PORT app:app
```text
# .env.example
# This file lists the environment variables required by your application.
# For production, set these values securely in Render.com environment settings.
# DO NOT commit your actual .env file with sensitive data to your Git repository.

# ISO 8583 Server Configuration
# The IP address or hostname of your Card Owner's ISO 8583 server.
# This server must be publicly accessible from Render.com.
ISO_SERVER_HOST="your_iso_server_ip_or_hostname"
# The port number of your Card Owner's ISO 8583 server.
ISO_SERVER_PORT="your_iso_server_port"

# Crypto Payout Configuration
# The URL of your blockchain API provider (e.g., Infura, Alchemy, TronGrid).
# Example for Infura Ethereum Mainnet: https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID
WEB3_PROVIDER_URL="https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"
# The public crypto wallet address where funds will be sent (your merchant's wallet).
MERCHANT_WALLET_ADDRESS="0xYourRealMerchantWalletAddressHere"
# The private key of the wallet that will send the crypto (your sending wallet).
# This is EXTREMELY SENSITIVE. Handle with utmost care.
# Consider using a secure key management service in production.
SENDER_WALLET_PRIVATE_KEY="0xYourSendingWalletPrivateKeyHere"
# The public address corresponding to the SENDER_WALLET_PRIVATE_KEY.
# This is often derived from the private key, but explicitly setting it can be useful.
SENDER_WALLET_ADDRESS="0xYourSendingWalletAddressHere"
```json
[
  {
    "constant": true,
    "inputs": [],
    "name": "name",
    "outputs": [
      {
        "name": "",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "_spender",
        "type": "address"
      },
      {
        "name": "_value",
        "type": "uint256"
      }
    ],
    "name": "approve",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "totalSupply",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "_from",
        "type": "address"
      },
      {
        "name": "_to",
        "type": "address"
      },
      {
        "name": "_value",
        "type": "uint256"
      }
    ],
    "name": "transferFrom",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "decimals",
    "outputs": [
      {
        "name": "",
        "type": "uint8"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "_owner",
        "type": "address"
      }
    ],
    "name": "balanceOf",
    "outputs": [
      {
        "name": "balance",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "symbol",
    "outputs": [
      {
        "name": "",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "_to",
        "type": "address"
      },
      {
        "name": "_value",
        "type": "uint256"
      }
    ],
    "name": "transfer",
    "outputs": [
      {
        "name": "",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "_owner",
        "type": "address"
      },
      {
        "name": "_spender",
        "type": "address"
      }
    ],
    "name": "allowance",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "payable": true,
    "stateMutability": "payable",
    "type": "fallback"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "owner",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "spender",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "value",
        "type": "uint256"
      }
    ],
    "name": "Approval",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "from",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "to",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "value",
        "type": "uint256"
      }
    ],
    "name": "Transfer",
    "type": "event"
  }
]
