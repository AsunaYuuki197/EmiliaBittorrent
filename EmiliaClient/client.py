import requests
import hashlib
import random
import socket
import json
import threading
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import queue
import numpy as np
import streamlit as st
import traceback, sys
import subprocess

from messages import *

# Define unreserved characters as a global variable
unreserved_chars = "%+" + ";?:@=&,$/" + "-_!.~*()" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" + "0123456789"

# Define hex characters
hex_chars = "0123456789ABCDEF"
peer_connected = {}
messages = {
    # remain connection
    'keep-alive': b'\x00' * 4,
    # doesn't want to upload
    'choke': b'\x00\x00\x00\x01\x00',
    # free to upload
    'unchoke': b'\x00\x00\x00\x01\x01',
    # want to download
    'interested': b'\x00\x00\x00\x01\x02',
    # dont want to download
    'not interested': b'\x00\x00\x00\x01\x03',
    # inform success download which piece index
    'have': b'\x00\x00\x00\x05\x04' + b'\x00\x00\x00\x00',
    # bitfield of pieces that have been successfully downloaded - bitfield: <len=0001+X><id=5><bitfield>
    'bitfield': b'\x00\x00\x00\x01\x05',
    # request piece at index, offset of block begin at, and length of the block being requested
    'request': b'',
    # send piece: <len=0009+X><id=7><index><begin><block>
    'piece': b'\x00\x00\x00\x09\x07',
    # cancel block request <len=0013><id=8><index><begin><length>
    'cancel': b'\x00\x00\x00\x13\x08',
    'port': b'\x00\x00\x00\x03\x09' + int.to_bytes(6881, length=4)

}

# session[peer_id][info_hash] = session_data - session[peer_id]["last_active_info_hash"] = info_hash
session = {}
stop = threading.Event()
pause = threading.Event()
pause.set()
write_lock = threading.Lock()
choose_index_lock = threading.Lock()
peer_get_lock = threading.Lock()
# bitfield_dict[info_hash] = {adrress: bitfield}
bitfield_dict = {}
my_bitfield_dict = {}
# save processed file
file_info_dict = {}
rarest_piece = []
max_block = 16384
file_progress = {}
log = open("log", "a", encoding='utf-8')


def create_torrent_file(file_path, trackers, piece_length=16384, output_name="output"):
    """
    Create a .torrent file for the specified file or directory.
    """
    def calculate_pieces(file_path, piece_length):
        """
        Generate 20 bytes hash of pieces for the file using SHA-1.
        """
        pieces = b""
        with open(file_path, "rb") as f:
            while True:
                piece = f.read(piece_length)
                if not piece:
                    break
                pieces += hashlib.sha1(piece).digest()
        return pieces

    def get_file_info(file_path):
        """
        Metadata information.
        """
        if os.path.isfile(file_path):
            length = os.path.getsize(file_path)
            pieces = calculate_pieces(file_path, piece_length)
            file_name = os.path.basename(file_path)
            return {"length": length, "pieces": pieces, "name": file_name}
        else:
            files_info = []
            pieces = b""
            top_level_folder = os.path.basename(file_path)
            for root, _, files in os.walk(file_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    length = os.path.getsize(full_path)
                    rel_path =  os.path.relpath(full_path, file_path).split(os.path.sep)
                    # rel_path =  os.path.join(top_level_folder, os.path.relpath(full_path, file_path)).split(os.path.sep)
                    pieces += calculate_pieces(full_path, piece_length)
                    files_info.append({"length": length, "path": rel_path})
            return {"files": files_info, "pieces": pieces, "name": os.path.basename(file_path)}

    info = get_file_info(file_path)
    info["piece length"] = piece_length

    torrent_dict = {
        "announce": trackers[0],
        "info": info,
    }

    if len(trackers) > 1:
        torrent_dict["announce-list"] = [[tracker] for tracker in trackers]

    # Write the .torrent file
    with open(f'{os.path.dirname(file_path)}\\{output_name}.torrent', "wb") as f:
        f.write(bencodepy.encode(torrent_dict))

    return output_name


def urlencoded(s: str, offset: int):
    """
    Escape a string based on unreserved characters and an offset (for lookup unreserved chars).
    """
    assert s is not None, "Input string must not be None"
    assert len(s) >= 0, "Length of input string must be non-negative"
    assert offset >= 0, "Offset must be non-negative"
    assert offset < len(unreserved_chars) - 1, "Offset must be within unreserved_chars length"

    ret = []
    for char in s:
        if chr(char) in unreserved_chars[offset:] and chr(char) != '\0':
            # Byte -> char in set
            ret.append(chr(char))
        else:
            # Convert the character to its hexadecimal representation (nn) follow format %nn
            ret.append('%')
            ret.append(hex_chars[char >> 4])  # Get hex of first four bits of character
            ret.append(hex_chars[char & 15])  # Get hex of last four bits of character

    return ''.join(ret)


def escape_string(s: str):
    """
    Escape a string using the urlencoded with a default offset of 11.
    """
    return urlencoded(s, 11)


def get_metadata(torrent_file_path):  
    """
    From torrent file get info hash in case dont have info_hash, 
    also extract metadata from torrent
    """

    # Read the torrent file
    with open(torrent_file_path, 'rb') as f:
        torrent_data = f.read()
    
    # Decode the bencoded data
    torrent = bencodepy.decode(torrent_data)
    
    # Get list tracker
    
    trackers = []
    info = length = file_name = piece_length = pieces = subfiles = None
    files = []
    
    for key in torrent.keys():
        match key:
            case b'announce':
                trackers.append(str(torrent[b'announce'])[2:-1])
            case b'announce-list':
                for tracker in torrent[b'announce-list']:
                    trackers.append(str(tracker[0])[2:-1])
            case b'info':
                info = torrent[b'info']
    

    for key in info.keys():
        match key:
            case b'length':
                length = info[b'length']
            case b'name':
                file_name = info[b'name']
            case b'piece length':
                piece_length = info[b'piece length']        
            case b'pieces':
                pieces = info[b'pieces']  
            case b'files':
                subfiles = info[b'files']  
                files = []
                if length == None:
                    length = 0
                    for subfile in subfiles:
                        files.append({"length": subfile[b'length'], "path": [p.decode('utf-8') for p in subfile[b'path']]})
                        length += subfile[b'length']
    

    # Encode the info dictionary back to bencoded format
    info_bencoded = bencodepy.encode(info)
    
    # Calculate the SHA1 hash of the bencoded info
    info_hash = hashlib.sha1(info_bencoded).hexdigest()
    pieces =  [pieces[i:i + 20] for i in range(0, len(pieces), 20)]
  



    return trackers, info_hash, length, file_name, piece_length, pieces, files


def decode_peers(peers_binary):
    """
    Get ip and port from peers response
    """
    peers = []
    
    if len(peers_binary) % 6 != 0:
        log.write("Peers len error\n")

    for i in range(0,len(peers_binary),6):
        ip = '.'.join(map(str,peers_binary[i:i+4]))        
        port = (int(peers_binary[i+4]) << 8) + int(peers_binary[i+5])
        peers.append((ip, port))

    return peers


def get_content(data):
    """
    <length prefix><message Id><payload>
    4 bytes big-endian value - Decimal byte - message dependent
    1 byte = 8 bits
    """
    content = {}

    if data[1:20] == b'BitTorrent protocol':
        content['pstrlen'] =  data[0]
        content['pstr'] =  data[1:20]
        content['reserved'] =  data[20:28]
        content['info_hash'] = bytes.hex(data[28:48])
        content['peer_id'] =  data[48:68].decode('utf-8', errors='replace')   
        data = data[68:]


    next_index = 0
    while next_index < len(data):
        if len(data) > 4:
            length_prefix = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3]

            try:
                match length_prefix:
                    case 0:
                        pass
                    case 1:
                        match data[4]:
                            case 0:
                                content['choke'] = 1
                                next_index = 5
                            case 1:
                                content['unchoke'] = 1
                                next_index = 5
                            case 2:
                                content['interest'] = 1
                                next_index = 5
                            case 3:
                                content['not interest'] = 1
                                next_index = 5
                    case 5:
                        match data[4]:
                            case 4:
                                content['have'] = int.from_bytes(data[5:9])
                                next_index = 9
                    case 13:
                        match data[4]:
                            case 6:
                                content['request'] = {}
                                content['request']['index'] = data[5:9]
                                content['request']['begin'] = data[9:13]               
                                content['request']['length'] = data[13:17]
                                next_index = 17
                            case 8:
                                content['cancel'] = {}
                                content['cancel']['index'] = data[5:9]
                                content['cancel']['begin'] = data[9:13]               
                                content['cancel']['length'] = data[13:17]         
                                next_index = 17
                    case _:
                        
                        match data[4]:
                            case 5:
                                bitfield_len = length_prefix - 1
                                content['bitfield'] = [(byte >> i) & 1 for byte in data[5:bitfield_len+5] for i in range(7, -1, -1)]
                                next_index = bitfield_len+5
                            case 7:
                                piece_len = length_prefix - 9
                                content['piece'] = {}
                                content['piece']['index'] = int.from_bytes(data[5:9])
                                content['piece']['begin'] = int.from_bytes(data[9:13])
                                content['piece']['block'] = data[13:piece_len+13]
                                next_index = piece_len+13


                if next_index == 0:
                    return content
                data = data[next_index:]
            except:
                return content
            
            data = data[next_index:]
        else:
            break    
    # print("content ", content)
    return content


def check_have(info_hash):
    """
    Check own the file have this info_hash
    """
    if os.path.exists(f'localrepo/{info_hash}.txt'):
        with open(f'localrepo/{info_hash}.txt', 'r', encoding='utf-8') as fp:
            file_info = ast.literal_eval(fp.read())
            if os.path.exists(file_info['path']):
                return info_hash
    return b''


def update_state(addr, info_hash, index):
    """
    update bitfield
    index can be index or bitfield list
    """
    if type(index) == list:
        peer_connected[info_hash][addr]['bitfield'] = index
    else:
        peer_connected[info_hash][addr]['bitfield'][index] = 1


def check_process(info_hash):
    # progress of info_hash
    if 'progress' not in st.session_state:
        st.session_state.progress = {}
    st.session_state.progress[info_hash] = 0
    col1, col2 = st.columns([4, 4]) 

    with col1:
        st.write(f"{os.path.basename(torrent_file_path)} progress:")

    with col2:
        progress_bar = st.progress(st.session_state.progress[info_hash])
        while True:
            if stop.is_set():
                break
            if my_bitfield_dict[info_hash].count(1) == len(my_bitfield_dict[info_hash]):
                stop.set()
                break
            st.session_state.progress[info_hash] = int(sum(my_bitfield_dict[info_hash])/len(my_bitfield_dict[info_hash]))

            progress_bar.progress(st.session_state.progress[info_hash])

            time.sleep(0.1)  


def check_hash(piece, info_hash, index):
    # print(piece)
    if all(piece):
        complete_piece = b''.join(piece)
        expected_hash = hashlib.sha1(complete_piece).digest()
        # You can compare this with the expected hash to verify integrity
        
        if file_info_dict[info_hash]['pieces'][index] == expected_hash:
            print("Verified piece hash")
            return True
    else:
        log.write(f"Not all blocks received. {piece}")
        print(f"Not all blocks received. {index}")
    
    return False


def write_to_file(info_hash, data_piece, index):
    data_piece = b''.join(data_piece)
    with write_lock:
        try:
            file_info = ast.literal_eval(open(f'localrepo/{info_hash}.txt', 'r', encoding='utf-8').read())

            piece_length = file_info['piece length']
            if file_info['length'] < piece_length:
                piece_length = file_info['length']
            offset = index * piece_length

            # Determine the file and directory structure from the file_info info
            current_offset = 0
            if len(file_info['files']) == 0:
                with open(file_info['path'], 'w+b') as f:
                    f.seek(offset)
                    f.write(data_piece)
                    print(f'Write success {index}')
                    return True
            else:
                for file in file_info['files']:
                    file_length = file['length']
                    
                    if current_offset + file_length > offset:
                        file_path = os.path.join(file_info['path'],*file['path'])
                        if not os.path.exists(os.path.dirname(file_path)):
                            os.makedirs(os.path.dirname(file_path))

                        # Open the file in binary mode and write the block at the correct offset
                        with open(file_path, 'w+b') as f:
                            f.seek(offset - current_offset)
                            f.write(data_piece)
                            print(f'Write success {index}')

                        break
                    
                    current_offset += file_length
                return True
        except Exception as e:
            log.write(f'Error write {e}')
            print(f'Error write {e}')
    return False


def get_rarest_pieces_order(info_hash):

    num_completed_pieces = [0]*len(my_bitfield_dict[info_hash])

    for values in bitfield_dict[info_hash].values():
        for idx, value in enumerate(values):
            if value == 1:
                num_completed_pieces[idx] += 1


    
    # print(num_completed_pieces)

    sorted_pairs = sorted(enumerate(num_completed_pieces), key=lambda x: x[1])

    sorted_values = [pair[1] for pair in sorted_pairs if pair[1] > 0]
    sorted_indices = [pair[0] for pair in sorted_pairs if pair[1] > 0]
    
    return sorted_indices, sorted_values


def announce_to_tracker(peer_id, port, left, event, trackers, info_hash=None):
    """
    Announce to tracker to:
    - Inform files in local
    - Infrom event (started, stopped, completed)
    - Get List Peer
    """
    list_of_peer = []


    def get_list_peers(info_hash):
        if info_hash == None:
            raise ValueError("Info hash are not specific.")

        escaped_info_hash = escape_string(hex_to_bytes(info_hash))
        
        for tracker in trackers:
            try:
                response = requests.get(f'{tracker}?info_hash={escaped_info_hash}&peer_id={peer_id}&port={port}&uploaded=0&downloaded=0&left=564289308&compact=1', timeout=2)
            
            except (requests.exceptions.InvalidSchema, Exception, requests.exceptions.RequestException) as e:
                # Catch all request-related exceptions and any other exceptions
                log.write(f"An error occurred: {e}\n")
                continue

            if response.status_code == 200:
                response = bencodepy.decode(response.content)
                for key in response.keys():
                    match key:
                        case b'failure reason':
                            log.write(str(response[b'failure reason']))
                        case b'peers':
                            list_of_peer.extend(decode_peers(response[b'peers']))
        

        # return decode_peers(response[b'peers'])
        return


    if event == "started" and left != 0:
        get_list_peers(info_hash)
        return list_of_peer


def upload(conn, addr, request):
    if addr in session.keys():
        info_hash = session[addr]["last_active_info_hash"]

    def read_piece_from_file(file_path, index, begin, length):
        """
        Read a piece of data from the file.
        """
        # open the file, seek to the correct position, and read the bytes.
        try:
            with open(file_path, "rb") as f:
                f.seek(begin + index * piece_length)  # Adjust for piece size
                return f.read(length)
        except Exception as e:
            log.write(f"Error reading piece from file: {e}")
            return None    

    if os.path.exists(f'localrepo/{info_hash}.txt'):
        with open(f'localrepo/{info_hash}.txt', 'r', encoding='utf-8') as fp:
            file_info = ast.literal_eval(fp.read())
            piece_length = file_info['piece length']
            piece_data = read_piece_from_file(file_info['path'], int.from_bytes(request['index']),  int.from_bytes(request['begin']),  int.from_bytes(request['length']))
            
            piece_data_length = 9 + len(piece_data)

            messages['piece']= piece_data_length.to_bytes(length=4) + b'\x07' + request['index'] + request['begin'] + piece_data
            return messages['piece']
    else:
        return b''

def download(s, peer_address, info_hash, index):
    global file_info_dict, my_bitfield_dict
    piece_length = file_info_dict[info_hash]['piece length'] if file_info_dict[info_hash]['piece length'] < file_info_dict[info_hash]['length'] else file_info_dict[info_hash]['length']
    block_size = piece_length if piece_length < max_block else max_block 
    data_piece = [None] * (piece_length // block_size)
    

    for i in range(0, piece_length, block_size):
        print(f'Downloading piece {index} begin at {i if i < piece_length else piece_length}')
        s.sendall(request_message(int(index), i if i < piece_length else piece_length, block_size))        
        data = b''
        s.settimeout(3)
        try:
            print(f"My bitfield at {index}:",my_bitfield_dict[info_hash][index])
            while my_bitfield_dict[info_hash][index] == 2:
                # time.sleep(0.2)
                # buffer == block size + message length + message id + index + begin
                response = s.recv(block_size + 4 + 1 + 4 + 4)
                print('Recv data')
                if not response:
                    break
                data += response
                if len(data) >= (block_size + 4 + 1 + 4 + 4):
                    data = get_content(data)
                    # print('This is response...', data)
                    if 'piece' not in data.keys():
                        log.write(f"Piece not in {data}")
                        return False
                    elif data['piece']['index'] == index:
                        data_piece[int(data['piece']['begin']) // block_size] = data['piece']['block']
                        print([id for id, x in enumerate(data_piece) if x == None])
                    break
        except socket.timeout:
            continue      
        except Exception as e:
            log.write(f"Error connecting to peer {peer_address}: {e}")
            log.write(str(traceback.format_exc()))

    
    s.settimeout(None)
    if check_hash(data_piece, info_hash, index) and write_to_file(info_hash, data_piece, index):
        with choose_index_lock: 
            if my_bitfield_dict[info_hash][index] == 2:
                my_bitfield_dict[info_hash][index] = bitfield_dict[info_hash][peer_address][index]
                return True
    with choose_index_lock: 
        if my_bitfield_dict[info_hash][index] == 2:
            my_bitfield_dict[info_hash][index] = 0
    
    return False
            


def exchange_message(s, response, peer_address, info_hash):
    global rarest_piece, file_info_dict, my_bitfield_dict

    log.write(str(get_content(response)))
    if info_hash == bytes.hex(response[28:48]) and response[1:20] == b'BitTorrent protocol':
        s.settimeout(None)
        """
        Kiểm tra response này có cách trường cần thiết để tải piece ko
        1. nếu có bitfield => thêm vào dict
        2. nếu ko có bitfield => send interested unchoke bitfield message
        2.1 Wait nếu ko có rep thì close
        2.2 Nếu có bitfield quay lại bước 1
        3. Request random piece trong bitfield peer khác gửi (max 5 lượt để lấy một vài pieces) 
        4. Thực hiện giải thuật rarest-piece cho list bitfield để chọn các piece hiếm để tải cho mỗi thread
        5. Request piece  
        6. Còn 4 pieces thì đồng thời các thread đều gửi request cùng 1 piece
        7. Nếu piece nào của address nào đến trước thì cancel nhận response của các peer còn lại
        8. Liên tục kiểm tra process
        """

        # while True:
        data = get_content(response)
        print(data)

        if "bitfield" in data.keys():
            bitfield_dict[info_hash][peer_address] = data["bitfield"]
        else:
            s.sendall(bitfield_message(info_hash) + messages['interested'] + messages['unchoke'])
            
            data = b''
            start_time = time.time()
            while time.time() - start_time < 20:
                response = s.recv(1024)
                if not response or response == b'':
                    break
                data += response

            if "bitfield" in get_content(data).keys():
                bitfield_dict[info_hash][peer_address] = data["bitfield"]
            else:
                return False


        # start
        max_request = 5
        index_list = [i for i in range(len(my_bitfield_dict[info_hash])) if bitfield_dict[info_hash][peer_address][i]]

        while max_request:
            max_request -= 1
            # print(max_request)
            # choose random index    
            while len(index_list) > 0:
                print("Index list", index_list)
                index = random.choice(index_list)
                # print(f'Piece index select: {index}...')
                with choose_index_lock: 
                    if my_bitfield_dict[info_hash][index] == 0:
                        my_bitfield_dict[info_hash][index] = 2 # wait for request
                        break
                    else:
                        index_list.remove(index)
                            
            if len(index_list) != 0 and download(s, peer_address, info_hash, index):
                print(f"Piece: {my_bitfield_dict[info_hash][index]}")
                index_list.remove(index)
            # else:
            #     my_bitfield_dict[info_hash][index] = 0

        
        
        # rarest piece
        if len(rarest_piece) == 0:
            with choose_index_lock:
                rarest_piece, sorted_counts = get_rarest_pieces_order(info_hash)
        
        already_go = []
        time.sleep(1)
        while len(rarest_piece) - len(already_go) > 5:
            index = random.choice(rarest_piece[:10])
            print(f"Rarest first at {index}")
            if bitfield_dict[info_hash][peer_address][index] == 1:
                with choose_index_lock: 
                    if my_bitfield_dict[info_hash][index] == 0:
                        my_bitfield_dict[info_hash][index] = 2 # wait for request
                    else:
                        rarest_piece.remove(index)
                        continue
                if download(s, peer_address, info_hash, index):
                    with choose_index_lock:
                        rarest_piece.remove(index)     
                        continue
                else:
                    my_bitfield_dict[info_hash][index] = 0
            
            already_go.append(index)


        time.sleep(1)
        # endgame
        for index in rarest_piece:
            print(f"End game at {index}")

            if bitfield_dict[info_hash][peer_address][index] == 1:
                with choose_index_lock: 
                    if my_bitfield_dict[info_hash][index] == 0:
                        my_bitfield_dict[info_hash][index] = 2 # wait for request
                    else:
                        rarest_piece.remove(index)
                        continue
                if download(s, peer_address, info_hash, index):
                    with choose_index_lock:
                        rarest_piece.remove(index)

        # complete
        if my_bitfield_dict[info_hash].count(1) == len(my_bitfield_dict[info_hash]):
            return True
        
            # break

    return False

def handshake(peer_id, peers, info_hash):
    for peer_address in peers: 
        print(peer_address)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect(peer_address)
                s.sendall(handshake_message(peer_id, info_hash) + messages['interested'] + messages['unchoke'])
                s.settimeout(5)
                data = b''
                
                try:
                    while True:
                        response = s.recv(1024)
                        print("---")
                        print(f"Connected to peer {peer_address} successfully")
                        if not response or response == b'':
                            break

                        data += response
                        if len(data) > 75:
                            break
                except socket.timeout:
                    log.write(f"Error connecting to peer {peer_address}")
                except Exception as e:
                    log.write(f"Error connecting to peer {peer_address}: {e}")
                
                if data == b'' or len(data) <= 68:
                    s.close()
                else:
                    if exchange_message(s, data, peer_address, info_hash):
                        s.close()
                        break
                    s.close()
            except KeyboardInterrupt:
                s.close()
                break
            except Exception as e:
                # print(str(traceback.format_exc()))
                log.write(f"Error connecting to peer {peer_address}: {e}")
                log.write(str(traceback.format_exc()))

def start_handshake(peer_id, peer_queue, info_hash):
    while True:
        with peer_get_lock:
            peer_address = peer_queue.get()  # Get the next peer from the queue
        print(f"I am processing this {peer_address}")
        if peer_address == None:  # Exit condition
            break
        
        # Check for pause event
        pause.wait()
        if stop.is_set():
            break

        handshake(peer_id, [peer_address], info_hash)
        peer_queue.task_done() 


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # This doesn't have to be reachable, just a valid address
        s.connect(('8.8.8.8', 1))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = '127.0.0.1'  # Fallback to localhost
    finally:
        s.close()
    return ip_address


def get_public_ip():
    response = requests.get('https://api.ipify.org')
    return response.text



def check_have_file_and_inform(peer_id, event):
    for filename in os.listdir("localrepo"):
        if filename.endswith('.txt'):
            file_path = os.path.join("localrepo", filename)
            with open(file_path, 'r', encoding='utf-8') as file:
                file_info = ast.literal_eval(file.read())

                if os.path.exists(file_info['path']):
                    # Convert bitfield to usable format (if necessary)
                    file_info_bitfield = [(byte >> i) & 1 for byte in hex_to_bytes(file_info['bitfield']) for i in range(7, -1, -1)]
                    complete = sum(file_info_bitfield)/len(file_info_bitfield) * file_info['length']
                    left = int(file_info['length'] - complete)
                    if 'announce' in file_info.keys():
                        trackers = file_info['announce']
                        for tracker in trackers:
                            announce_to_tracker(peer_id, port, 0 if left < 0 else left, event, tracker, file_info['info_hash'])
                    else:
                        announce_to_tracker(peer_id, port, 0 if left < 0 else left, event, "https://emilia-tracker.onrender.com/announce", file_info['info_hash'])
                else:
                    print(f"Path does not exist: {file_info['path']}")





def handle_peer_connection(conn, addr):
    conn.settimeout(120)  # Timeout for disconnet if inactivity

    try:
        while True:
            data = conn.recv(1024)
            if not data or data == b'':
                break
            data = get_content(data)
            print(data)
            response = b''
            for key in data.keys():
                match key:
                    case 'pstrlen':
                        if data['pstrlen'] == b'\x13':
                            response += data['pstrlen']
                    case 'pstr':
                        if data['pstr'] == b'BitTorrent protocol':
                            response += data['pstr']
                    case 'reserved':
                        if data['reserved'] ==  b'\x00\x00\x00\x00\x00\x00\x00\x00':
                            response += data['reserved']
                    case 'info_hash':
                        response += check_have(data['info_hash'])
                    case 'peer_id':
                        response += peer_id
                        response += bitfield_message(data['info_hash'])
                        response += messages['unchoke']
                        session[addr] = {}
                        session[addr][data['info_hash']] = {'handshake'} 
                        session[addr]["last_active_info_hash"] = data['info_hash']
                    case 'choke':
                        conn.close()
                    case 'unchoke':
                        pass
                    case 'interest':
                        response += messages['unchoke']
                        messages['bitfield']= bitfield_message(data['info_hash'])
                        response += messages['bitfield']
                    case 'not interest':
                        conn.close()
                    case 'have':
                        update_state(addr, data['info_hash'], data['have'])
                    case 'request':
                        response += upload(conn, addr, data['request'])
                    case 'bitfield':
                        update_state(addr, data['info_hash'], data['bitfield'])
                    case 'cancel':
                        pass

            conn.sendall(response)
        
    except socket.timeout:
        log.write(f'Closing connection with {addr} because of inactivity tined out.\n')
        conn.close()
    except Exception as e:
        log.write(f"Error handling connection from {addr}: {e}\n")
    finally:
        conn.close()


def start_peer_server(server_address):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(server_address)
        server_socket.listen(10)
        log.write(f"Peer is listening on port {server_address}...\n")
        
        while True:
            if stop.is_set:
                server_socket.close()
                break
            conn, addr = server_socket.accept()
            if addr == (get_public_ip(), server_port):
                print("You are me")
                conn.close()
                continue
                
            threading.Thread(target=handle_peer_connection, args=(conn, addr, )).start()



if __name__ == "__main__":

    server_port = 6882 # Replace with your desired port

    local_ip = get_local_ip()
    public_ip = get_public_ip()

    peer_id = "-ET2309-abcdef123456"
    port = 6882

    server_thread = threading.Thread(target=start_peer_server, args=((local_ip, server_port), ))
    server_thread.start()
    
    # check file have and inform
    check_have_file_and_inform(peer_id, "started")

    if 'progress' not in st.session_state:
        st.session_state.progress = {}
    st.title("Emilia BitTorrent")

    # peer_id = ''.join(random.choice(unreserved_chars[11:]) for _ in range(12))
    # """
    # 1. Chạy app
    # 2. Check local repo (file_info + bitfield)
    # 3. Load lên UI + Announce cho tracker(started + left)
    # 4.1. bỏ torrent file vào 
    # 4.1.1 Check file đã có trên máy chưa - thông qua local repo - kiểm tra path + bitfield
    # 4.1.2 Click download (specific vị trí download nếu được) - tạo thread 
    # 4.1.3 Announce cho tracker (started + left) -> get_list_peer
    # 4.1.4 Establish handshake to every ip
    # 4.1.5 Lưu thông tin IP, PORT + Bitfield mà trả về
    # 4.1.6 Rarest pick
    # 4.1.7 Gửi request và tải -> trong quá trình tải có thể announce cho tracker liên tục để update tracker db
    # 4.1.8 Check piece hash
    # 4.1.9 Tải xong thì announce completed cho server 
    # """

    st.sidebar.subheader("Download File Area")
    download_folder = st.sidebar.text_input("Enter download directory (e.g: C:\\Users\\ACER\\Downloads): ", value="C:\\Users\\ACER\\Downloads")
    torrent_file_path = st.sidebar.text_input("Enter torrent file path (e.g: C:\\Users\\ACER\\Pictures)")
    is_download = st.sidebar.button("Download")
    if is_download:
    
        # info_hash = st.input("Info hash: ")
        # tracker address = st.input("Tracker address (default = Emilia Tracker)")
        # torrent_file_path="Re Zero Starting a Life in Another World [BD][1080p][HEVC 10bit x265][Dual Audio][Tenrai-Sensei].torrent"
        if download_folder and torrent_file_path:
            if torrent_file_path[0] == '"':
                torrent_file_path = torrent_file_path[1:-1]
            if download_folder[0] == '"':
                download_folder = download_folder[1:-1]



            trackers = []
            if torrent_file_path != None:
                trackers, info_hash, length, file_name, piece_length, pieces, subfiles = get_metadata(torrent_file_path)
                my_bitfield_dict[info_hash] = [0 for _ in range(math.ceil(length / piece_length))]

                # # last piece is not always have full length bit field, e.g: [1,0,0,0]

                file_info_dict[info_hash] = {
                        "announce": trackers,
                        "path": f"{download_folder}\{file_name.decode('utf-8')}",
                        "name": file_name.decode("utf-8"),
                        "info_hash": info_hash,
                        "length": length,
                        "piece length": piece_length,
                        "bitfield": "00" * math.ceil(math.ceil(length / piece_length)/8),
                        "files": subfiles,
                        "pieces": pieces
                    }

                if os.path.exists(f"localrepo\{info_hash}.txt"):
                    with open(f'localrepo\{info_hash}.txt', 'r', encoding='utf-8') as fp:
                        file_info = ast.literal_eval(fp.read())
                        my_bitfield_dict[info_hash] = [(byte >> i) & 1 for byte in hex_to_bytes(file_info['bitfield']) for i in range(7, -1, -1)]
                        # remove spare bit
                        my_bitfield_dict[info_hash] = my_bitfield_dict[info_hash][:math.ceil(length / piece_length)]
                else:
                    with open(f"localrepo\{info_hash}.txt", "w", encoding='utf-8') as fp:
                        fp.write(str(file_info_dict[info_hash]))
                    
            else:
                # send request to get torrent info
                pass
            trackers.append("https://emilia-tracker.onrender.com/announce")


            list_of_peers = announce_to_tracker(peer_id=peer_id, port=port, left=length,event="started", trackers=trackers, info_hash=info_hash)
            lenlp = len(list_of_peers)
            # list_of_peers = [("127.0.0.1",8081)]

            if is_download:
                bitfield_dict[info_hash] = {}
                # Hankshake for each thread
                threads = []
                peer_queue = queue.Queue()
                # Fill the queue with peer addresses
                for peer_address in list_of_peers:
                    peer_queue.put(peer_address)

                # check_process_thread = threading.Thread(target=check_process, args=(info_hash,))
                # check_process_thread.start()
                

                for i in range(0,lenlp, int(lenlp/5)):
                    t = threading.Thread(target=start_handshake, args=(peer_id,peer_queue,info_hash,))
                    t.daemon = True
                    t.start()
                    threads.append(t)

                try:
                    file_progress[info_hash] = 0
                    bar_progress = st.progress(0, f'{os.path.basename(torrent_file_path)} progress: ')
                    while True:                            
                        if stop.is_set():
                            break
                        
                        time.sleep(5)  
                        with choose_index_lock:
                            if my_bitfield_dict[info_hash].count(1) == len(my_bitfield_dict[info_hash]) or int(sum(my_bitfield_dict[info_hash])/len(my_bitfield_dict[info_hash]) * 100) >= 100:
                                stop.set()
                                break

                            file_progress[info_hash] = int(sum(my_bitfield_dict[info_hash])/len(my_bitfield_dict[info_hash]) * 100)
                            bar_progress.progress(file_progress[info_hash], f'{os.path.basename(torrent_file_path)} progress: ')

                    # Stop the workers
                    for _ in threads:
                        peer_queue.put(None)  # Signal to threads to exit
                    for t in threads:
                        t.join()  # Wait for all threads to finish
                    # check_process_thread.join()


                    with open(f'localrepo\{info_hash}.txt', 'w', encoding='utf-8') as fp:
                        file_info_dict[info_hash]['bitfield'] = ""
                        print(my_bitfield_dict[info_hash])
                        for i in range(0, len(my_bitfield_dict[info_hash]), 8):
                            bits = ""
                            for j in range(8):
                                bits += "0" if (i+j) >= len(my_bitfield_dict[info_hash]) else str(my_bitfield_dict[info_hash][i+j])
        
                            file_info_dict[info_hash]['bitfield'] += str(hex(int(bits, 2))[2:]) 

                        print(file_info_dict[info_hash])
                        fp.write(str(file_info_dict[info_hash]))     
                    check_have_file_and_inform(peer_id, "completed")
                    st.success(f"Succesfully downloaded {os.path.basename(torrent_file_path)}")
                except (KeyboardInterrupt, SystemExit):
                    print("\nKeyboard interrupt received. Stopping...")
                    stop.set()  # Stop on keyboard interrupt
        else:
            st.warning("Please enter all fields")




    st.sidebar.subheader("Create torrent area")
    file_path = st.sidebar.text_input('Path of your file/directory (e.g: "C:\\Users\\ACER\\Documents\\text.txt"') or None
    # piece_length = None
    trackers = st.sidebar.text_input("Input trackers: (e.g: 'https://emilia-tracker.onrender.com/announce' serapate only by comma ,)") or None 
      
    if st.sidebar.button("Create Torrent"):
        if file_path and trackers:
            file_path = file_path[1:-1]
            trackers = trackers.split(',')
            # trackers.append("https://emilia-tracker.onrender.com/announce")
            output_name = create_torrent_file(
                file_path= file_path,
                trackers=trackers,
                piece_length=16384,
                output_name=os.path.basename(file_path)
            )
            if output_name:
                st.sidebar.write(f"Torrent file created: {file_path}.torrent")
        else:
            st.warning("Please enter all fields")
    
    server_thread.join()
    
    # stop app
    if st.sidebar.button("Stop app"):
        check_have_file_and_inform(peer_id, "stopped")
        stop.set()
        os.system("taskkill /f /im streamlit.exe")
        st.stop()