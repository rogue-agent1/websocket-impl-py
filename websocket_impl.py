import struct,hashlib,base64,os
MAGIC='258EAFA5-E914-47DA-95CA-5A5AB0DC85B5'
def create_handshake_key():
    return base64.b64encode(os.urandom(16)).decode()
def accept_key(client_key):
    return base64.b64encode(hashlib.sha1((client_key+MAGIC).encode()).digest()).decode()
def encode_frame(payload,opcode=1,mask=True):
    if isinstance(payload,str): payload=payload.encode()
    frame=bytearray()
    frame.append(0x80|opcode)  # FIN + opcode
    length=len(payload)
    mask_bit=0x80 if mask else 0
    if length<126: frame.append(mask_bit|length)
    elif length<65536: frame.append(mask_bit|126); frame.extend(struct.pack('!H',length))
    else: frame.append(mask_bit|127); frame.extend(struct.pack('!Q',length))
    if mask:
        mask_key=os.urandom(4); frame.extend(mask_key)
        payload=bytes(b^mask_key[i%4] for i,b in enumerate(payload))
    frame.extend(payload)
    return bytes(frame)
def decode_frame(data):
    fin=(data[0]>>7)&1; opcode=data[0]&0x0f
    masked=(data[1]>>7)&1; length=data[1]&0x7f; offset=2
    if length==126: length=struct.unpack('!H',data[2:4])[0]; offset=4
    elif length==127: length=struct.unpack('!Q',data[2:10])[0]; offset=10
    if masked:
        mask_key=data[offset:offset+4]; offset+=4
        payload=bytes(data[offset+i]^mask_key[i%4] for i in range(length))
    else: payload=data[offset:offset+length]
    return {'fin':fin,'opcode':opcode,'payload':payload}
if __name__=="__main__":
    key=create_handshake_key()
    accept=accept_key(key)
    assert len(accept)>10
    frame=encode_frame("Hello, WebSocket!",mask=True)
    decoded=decode_frame(frame)
    assert decoded['payload']==b"Hello, WebSocket!"
    assert decoded['opcode']==1 and decoded['fin']==1
    frame2=encode_frame(b"binary data",opcode=2,mask=False)
    d2=decode_frame(frame2)
    assert d2['payload']==b"binary data" and d2['opcode']==2
    print(f"WS key: {key[:16]}..., frame: {len(frame)}B")
    print("All tests passed!")
