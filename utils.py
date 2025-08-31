import base64

def bytes_to_binary(data: bytes) -> str:
    """Convert bytes to a binary string.
    
    Args:
        data (bytes): The bytes to convert.
    
    Returns:
        str: Binary string representation.
    
    Raises:
        TypeError: If data is not bytes.
    """
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data)}")
    return ''.join(format(byte, '08b') for byte in data)

def binary_to_bytes(binary_data: str) -> bytes:
    """Convert a binary string to bytes.
    
    Args:
        binary_data (str): The binary string to convert.
    
    Returns:
        bytes: The converted bytes.
    
    Raises:
        TypeError: If binary_data is not a string.
    """
    if not isinstance(binary_data, str):
        raise TypeError(f"Expected str, got {type(binary_data)}")
    if not binary_data:
        return b''
    remainder = len(binary_data) % 8
    if remainder != 0:
        binary_data += '0' * (8 - remainder)
    byte_list = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return bytes(int(byte, 2) for byte in byte_list)

def fix_base64_padding(data: bytes) -> bytes:
    """Fix base64 padding if necessary.
    
    Args:
        data (bytes): The base64 data to fix.
    
    Returns:
        bytes: The padded base64 data.
    
    Raises:
        TypeError: If data is not bytes.
        ValueError: If data is invalid base64 even after padding.
    """
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data)}")
    try:
        base64.urlsafe_b64decode(data)
        return data
    except Exception:
        missing_padding = len(data) % 4
        if missing_padding:
            padded_data = data + b'=' * (4 - missing_padding)
            try:
                base64.urlsafe_b64decode(padded_data)
                return padded_data
            except Exception:
                raise ValueError("Invalid base64 data even after padding")
        raise ValueError("Invalid base64 data")