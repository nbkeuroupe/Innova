# iso_client.py
import socket
import struct # For packing/unpacking binary data (e.g., length prefixes, numeric fields)
import time   # Import the time module to use time.time()

# --- ISO 8583 Message Specification (YOU MUST DEFINE THIS ACCURATELY) ---
# This is a CRITICAL section. You need to get the exact specifications from your
# Card Owner's ISO 8583 Server documentation.
# Example conceptual specification:
ISO_MESSAGE_SPEC = {
    "MTI": {"length": 4, "encoding": "ascii"}, # Message Type Indicator (e.g., "0100")
    "DE_2_PAN": {"length_prefix": 2, "max_length": 19, "encoding": "ascii", "type": "LLVAR_N"}, # Primary Account Number
    "DE_4_AMOUNT": {"length": 12, "encoding": "ascii", "type": "N"}, # Amount, Transaction (e.g., 000000010500 for $10.50)
    "DE_11_STAN": {"length": 6, "encoding": "ascii", "type": "N"}, # System Trace Audit Number
    "DE_14_EXPIRY_DATE": {"length": 4, "encoding": "ascii", "type": "N"}, # Expiration Date (YYMM or MMYY)
    "DE_22_POS_ENTRY_MODE": {"length": 3, "encoding": "ascii", "type": "N"}, # Point of Service Entry Mode (e.g., 010 for manual)
    "DE_35_TRACK2_EQUIVALENT": {"length_prefix": 2, "max_length": 37, "encoding": "ascii", "type": "LLVAR_AN"}, # Track 2 Equivalent Data (often contains PAN, expiry, service code)
    "DE_39_RESPONSE_CODE": {"length": 2, "encoding": "ascii", "type": "N"}, # Response Code (e.g., "00" for approved)
    "DE_55_ICC_DATA": {"length_prefix": 3, "max_length": 255, "encoding": "hex", "type": "LLLVAR_B"}, # Integrated Circuit Card (ICC) Data - for EMV
    "DE_60_PRIVATE_DATA": {"length_prefix": 2, "max_length": 99, "encoding": "ascii", "type": "LLVAR_AN"}, # Private Data (often used for CVV, Auth Code)
    # ... add all other required Data Elements (DEs)
}

def generate_stan() -> str:
    """Generates a unique System Trace Audit Number (STAN)."""
    # In a real system, this should be persistent and incrementing for each transaction.
    # Using time.time() for a unique, but not necessarily sequential, STAN.
    return str(int(time.time() * 1000000))[-6:].zfill(6)


def pack_data_element(value, spec) -> bytes:
    """Packs a single data element according to its specification."""
    data_type = spec.get("type")
    encoding = spec.get("encoding", "ascii")
    length = spec.get("length")
    length_prefix_bytes = spec.get("length_prefix") # For LLVAR/LLLVAR

    packed_data = b''

    if data_type == "LLVAR_N": # Numeric, variable length, with 2-byte length prefix
        encoded_value = value.encode(encoding)
        if len(encoded_value) > spec["max_length"]:
            raise ValueError(f"Value '{value}' exceeds max length {spec['max_length']}")
        # LLVAR prefix is typically 2 BCD digits (1 byte) or 2 ASCII digits (2 bytes)
        # For simplicity, assuming ASCII length prefix here.
        packed_data += f"{len(encoded_value):0{length_prefix_bytes}d}".encode(encoding)
        packed_data += encoded_value
    elif data_type == "N": # Fixed length Numeric
        packed_data += str(value).zfill(length).encode(encoding)
    elif data_type == "AN": # Fixed length Alphanumeric
        packed_data += value.ljust(length).encode(encoding)
    elif data_type == "LLVAR_AN": # Alphanumeric, variable length, with 2-byte length prefix
        encoded_value = value.encode(encoding)
        if len(encoded_value) > spec["max_length"]:
            raise ValueError(f"Value '{value}' exceeds max length {spec['max_length']}")
        packed_data += f"{len(encoded_value):0{length_prefix_bytes}d}".encode(encoding)
        packed_data += encoded_value
    # Add more types (LLLVAR, BCD, etc.) as needed based on your spec
    else:
        raise ValueError(f"Unsupported data type: {data_type}")

    return packed_data


def unpack_data_element(data_bytes: bytes, offset: int, spec) -> tuple[any, int]:
    """Unpacks a single data element from bytes and returns its value and new offset."""
    data_type = spec.get("type")
    encoding = spec.get("encoding", "ascii")
    length = spec.get("length")
    length_prefix_bytes = spec.get("length_prefix")

    value = None
    read_bytes = 0

    if data_type == "LLVAR_N" or data_type == "LLVAR_AN":
        # Read length prefix
        len_str = data_bytes[offset : offset + length_prefix_bytes].decode(encoding)
        actual_len = int(len_str)
        offset += length_prefix_bytes
        # Read actual data
        value = data_bytes[offset : offset + actual_len].decode(encoding)
        read_bytes = length_prefix_bytes + actual_len
    elif data_type == "N" or data_type == "AN":
        value = data_bytes[offset : offset + length].decode(encoding)
        read_bytes = length
    # Add more types for unpacking
    else:
        raise ValueError(f"Unsupported data type for unpacking: {data_type}")

    return value, offset + read_bytes


def build_iso_message(card_number: str, amount: float, expiry_date: str, cvv: str, auth_code: str) -> bytes:
    """
    Constructs a real ISO 8583 authorization request message in binary format.
    YOU MUST CUSTOMIZE THIS BASED ON YOUR SERVER'S EXACT ISO 8583 SPECIFICATION.
    """
    mti = "0100" # Authorization Request MTI
    stan = generate_stan()
    amount_in_cents = str(int(amount * 100)).zfill(12) # Amount is typically 12 digits, in cents

    # Format expiry date to YYMM or MMYY as per your ISO server's requirement
    # Assuming MM/YY input, converting to YYMM for DE 14
    mm, yy = expiry_date.split('/')
    formatted_expiry = yy + mm # Example: "2512" for 12/25

    # --- Constructing the Bitmap (Conceptual) ---
    # The bitmap indicates which Data Elements are present.
    # This is a simplified example. A real bitmap is a complex binary field.
    # For MTI 0100, common fields are 2, 4, 11, 14, 22, 41, 42, 49, 60 (for CVV/Auth Code).
    # You would set bits in an 8-byte (or 16-byte) binary field.
    # Example: If DE 2, 4, 11, 14, 22, 41, 42, 49, 60 are present:
    # This is highly specific to your implementation.
    # For now, we'll assume a fixed bitmap that covers our conceptual fields.
    # A real bitmap might look like: b'\x72\x00\x00\x00\x00\x00\x00\x00' (if only first set of bits are used)
    primary_bitmap = b'\x72\x00\x00\x00\x00\x00\x00\x00' # Placeholder - REPLACE WITH REAL BITMAP LOGIC

    # --- Packing Data Elements ---
    # Order of DEs must match the bitmap and your specification.
    packed_mti = mti.encode(ISO_MESSAGE_SPEC["MTI"]["encoding"])
    packed_pan = pack_data_element(card_number, ISO_MESSAGE_SPEC["DE_2_PAN"])
    packed_amount = pack_data_element(amount_in_cents, ISO_MESSAGE_SPEC["DE_4_AMOUNT"])
    packed_stan = pack_data_element(stan, ISO_MESSAGE_SPEC["DE_11_STAN"])
    packed_expiry = pack_data_element(formatted_expiry, ISO_MESSAGE_SPEC["DE_14_EXPIRY_DATE"])

    # Example: DE 22 POS Entry Mode (e.g., '010' for manual entry)
    packed_pos_entry_mode = pack_data_element("010", ISO_MESSAGE_SPEC["DE_22_POS_ENTRY_MODE"])

    # Example: DE 60 Private Data (often used for CVV, Auth Code, etc.)
    # You might combine CVV and Auth Code into one field or send them separately
    # depending on your server's protocol.
    private_data_content = f"CVV:{cvv}"
    if auth_code:
        private_data_content += f";AUTH:{auth_code}"
    packed_private_data = pack_data_element(private_data_content, ISO_MESSAGE_SPEC["DE_60_PRIVATE_DATA"])

    # Assemble the full message (without length prefix yet)
    raw_message_bytes = (
        packed_mti +
        primary_bitmap +
        packed_pan +
        packed_amount +
        packed_stan +
        packed_expiry +
        packed_pos_entry_mode +
        packed_private_data
        # + ... add other packed DEs like Terminal ID, Merchant ID, Currency Code
    )

    # --- Add Length Prefix (if required by your ISO server) ---
    # Many ISO 8583 implementations prefix the message with a 2-byte length.
    # Common formats:
    # - 2-byte binary length (e.g., struct.pack('>H', len(raw_message_bytes)))
    # - 4-byte ASCII length (e.g., f"{len(raw_message_bytes):04d}".encode('ascii'))
    # Check your server's documentation for this.
    message_length = len(raw_message_bytes)
    # Assuming 2-byte big-endian length prefix (common)
    length_prefix = struct.pack('>H', message_length) # '>H' for unsigned short, big-endian

    final_message = length_prefix + raw_message_bytes
    return final_message


def parse_iso_response(response_data: bytes) -> dict:
    """
    Parses an ISO 8583 response message from binary format.
    YOU MUST CUSTOMIZE THIS BASED ON YOUR SERVER'S EXACT ISO 8583 RESPONSE SPECIFICATION.
    """
    if not response_data:
        return {"status": "error", "message": "Empty response from ISO server."}

    offset = 0
    # --- Parse Length Prefix (if present in response) ---
    # If the server sends a length prefix, parse it first.
    # Assuming 2-byte big-endian length prefix.
    try:
        response_message_length = struct.unpack('>H', response_data[offset:offset+2])[0]
        offset += 2
        # Ensure we have enough data after parsing length
        if len(response_data) - offset < response_message_length:
            print(f"ISO Client: Incomplete response. Expected {response_message_length} bytes, got {len(response_data) - offset}.")
            return {"status": "error", "message": "Incomplete ISO response received."}
        # Slice the actual ISO message part
        actual_iso_message_bytes = response_data[offset : offset + response_message_length]
        offset = 0 # Reset offset for parsing the actual message
    except struct.error:
        # If no length prefix, assume the whole response_data is the message
        actual_iso_message_bytes = response_data
        print("ISO Client: No length prefix found in response, processing raw bytes.")
    except Exception as e:
        print(f"ISO Client: Error parsing response length prefix: {e}")
        return {"status": "error", "message": "Error parsing ISO response length."}

    try:
        # --- Parse MTI ---
        mti_spec = ISO_MESSAGE_SPEC["MTI"]
        response_mti = actual_iso_message_bytes[offset : offset + mti_spec["length"]].decode(mti_spec["encoding"])
        offset += mti_spec["length"]

        # --- Parse Bitmap ---
        # A real bitmap is 8 bytes for primary, possibly another 8 for secondary, etc.
        # This is a placeholder. You need to parse the actual bitmap and use it
        # to determine which DEs are present and their order.
        primary_bitmap_bytes = actual_iso_message_bytes[offset : offset + 8]
        offset += 8
        # You would then convert primary_bitmap_bytes to a bitmask to check for DEs.

        # --- Extract Response Code (DE 39) ---
        # This is highly dependent on the order of DEs in the response,
        # which is determined by the bitmap and your spec.
        # For this example, we'll assume DE 39 is directly after the bitmap for now.
        # In reality, you'd need to unpack all preceding DEs to find the correct offset.
        # You'll need to define the order of DEs in the response based on your server's spec.
        # For a minimal example, let's assume DE 39 is the first DE after the bitmap.
        response_code_spec = ISO_MESSAGE_SPEC["DE_39_RESPONSE_CODE"]
        response_code, new_offset = unpack_data_element(actual_iso_message_bytes, offset, response_code_spec)
        # offset = new_offset # Update offset after unpacking DE 39

        if response_mti == "0110" and response_code == "00":
            return {"status": "approved", "message": "Transaction Approved"}
        else:
            return {"status": "declined", "message": f"Transaction Declined (Code: {response_code})"}

    except IndexError:
        print(f"Error: Not enough data to parse ISO response. Raw: {response_data.hex()}")
        return {"status": "error", "message": "Incomplete or malformed ISO response."}
    except Exception as e:
        print(f"An unexpected error occurred during ISO response parsing: {e}. Raw response: {response_data.hex()}")
        return {"status": "error", "message": f"ISO response parsing error: {e}"}


def send_iso_request(host: str, port: int, card_number: str, amount: float, expiry_date: str, cvv: str, auth_code: str) -> dict:
    """
    Attempts to send an ISO 8583 authorization request to the specified server via socket.
    Includes expiry_date, cvv, and auth_code.
    """
    iso_message_bytes = build_iso_message(card_number, amount, expiry_date, cvv, auth_code)
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
