import bencodepy
import os, ast

def hex_to_bytes(hex_string: str):
    """
    Convert a hexadecimal string to a byte string.
    """
    # Hex string must has an even length
    if len(hex_string) % 2 != 0:
        raise ValueError("Hexadecimal string must have an even length.")
    
    return bytes.fromhex(hex_string)


def get_bitfield(info_hash):
    """
    Get bitfield and convert to hex
    """
    if os.path.exists(f'localrepo/{info_hash}.txt'):
        with open(f'localrepo/{info_hash}.txt', 'r', encoding='utf-8') as fp:
            file_info = ast.literal_eval(fp.read())
            return hex_to_bytes(file_info['bitfield'])
    else:
        return b''

def handshake_message(peer_id, info_hash):
    pstrlen = b'\x13'  # Length of "BitTorrent protocol"
    pstr = b'BitTorrent protocol'
    reserved = b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Reserved 8 bytes (all zero)
    # Construct the handshake message
    return pstrlen + pstr + reserved + hex_to_bytes(info_hash) + peer_id.encode('utf-8')


def extended_message():
    extended_msg_id = 20    # Extended message ID
    handshake_id = 0        # Extended handshake ID
    
    # Payload for the extended handshake (bencoded dictionary)
    payload = {
        "m": {
            "ut_metadata": 1,  # Support for metadata exchange
            "ut_pex": 2        # Support for peer exchange (PEX)
        },
        "v": "EmiliaTorrentClient 1.0",  # Client name
        "p": 6881
    }
    
    bencoded_payload = bencodepy.encode(payload)
    payload_length = len(bencoded_payload) + 2  # 2 bytes for IDs
    
    # Construct full message: <length prefix><extended message ID><handshake ID><payload>
    msg = payload_length.to_bytes(4, byteorder="big") + bytes([extended_msg_id]) +  bytes([handshake_id]) + bencoded_payload

    return msg


def bitfield_message(info_hash):
    bitfield = get_bitfield(info_hash)
    bitfield_length = 1 + len(bitfield)
    return bitfield_length.to_bytes(length=4) + b'\x05' + bitfield


def request_message(index, begin, length):
    return  b'\x00\x00\x00\x0d\x06' + index.to_bytes(length=4) + begin.to_bytes(length=4) + length.to_bytes(length=4)


# s.settimeout(20)
# bitfield = get_bitfield(info_hash)
# bitfield_length = 1 + len(bitfield)

# messages['bitfield']= bitfield_length.to_bytes(length=4) + b'\x05' + bitfield
# s.sendall(extended_message()+ messages['bitfield'] + messages['port'] + messages['unchoke'] + messages['interested'])