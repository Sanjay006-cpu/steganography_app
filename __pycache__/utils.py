def bytes_to_binary(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data)}")
    return ''.join(f'{byte:08b}' for byte in data)

def binary_to_bytes(binary_data: str) -> bytes:
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
    if not isinstance(data, bytes):
        raise TypeError(f"Expected bytes, got {type(data)}")
    try:
        base64.urlsafe_b64decode(data)
        return data
    except Exception:
        missing_padding = len(data) % 4
        if missing_padding:
            return data + b'=' * (4 - missing_padding)
        return data