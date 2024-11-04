import bencodepy
import hashlib
import ast
# utils.py
from firebase_admin import storage

def upload_to_firebase(file, filename):
    # Access the default Firebase bucket
    bucket = storage.bucket()

    # Create a blob for the file in Firebase Storage
    blob = bucket.blob(filename)
    
    # Upload the file
    blob.upload_from_file(file)
    
    # Make the file publicly accessible
    blob.make_public()
    return blob.public_url


def get_metadata(torrent_file):  
    """
    From torrent file get info hash in case dont have info_hash, 
    also extract metadata from torrent
    """
    
    # Decode the bencoded data
    torrent = bencodepy.decode(torrent_file.read())
    
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
    # pieces =  [pieces[i:i + 20] for i in range(0, len(pieces), 20)]
  
    return {
        'name': file_name.decode('utf-8'),
        'info_hash': info_hash,
        'announce': str(trackers),
        'files': str(files),
        'piece_length': piece_length,
        'pieces': pieces,
        'length': length
    }

def display_subfiles(subfiles):
    subfiles = ast.literal_eval(subfiles)
    paths = []
    for subfile in subfiles:
        paths.append((subfile['path'], subfile['length']))

    root = {}
    for path, length in paths:
        current_level = root
        for part in path[:-1]:
            if part not in current_level:
                current_level[part] = {}
            current_level = current_level[part]
        
        # Add the file with its length at the end
        current_level[path[-1]] = {'length': length}
    return root


def display_tree(node, indent=""):
    for key, subtree in node.items():
        
        if "length" in subtree.keys():
            print(indent + key.decode('utf-8') + " (" + str(subtree['length']) +")")
        else:
            print(indent + key.decode('utf-8'))
            if isinstance(subtree, dict):
                display_tree(subtree, indent + "    ")

# display_tree(display_subfiles(subfiles))


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