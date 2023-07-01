#! /usr/bin/python3

class LocDB:
  def __init__(self,fn="/var/lib/location/database.db",debug=1):
    f=open(fn,"rb")
    magic=f.read(8)    # 7 bytes magic + 1 byte version
    if debug:
        print(magic[0:7],magic[7])
    if magic!=b'LOCDBXX\x01':
        print("Invalid database format")
        return None

    header=f.read(64)
    if debug>1:
        print(header[0:16].hex(' '))
        print(header[16:32].hex(' '))
        print(header[32:48].hex(' '))
        print(header[48:64].hex(' '))

#                createdate|     vendor|      descr
#   00 00 00 00 64 9f b3 b0 00 00 00 01 00 00 00 10

#   license    | AS-offset | AS-length | ND-offset
#   00 00 00 a2 00 00 20 00 00 0b d7 28 02 69 f0 00

#    ND-length | NT-offset | NT-length | CO-offset
#   00 f9 17 a0 00 0c 00 00 02 5d e5 90 03 63 10 00

#    CO-length | Pool-offs | Pool-len  | sig1| sig2
#   00 00 07 f0 03 63 20 00 00 19 e5 e7 00 8b 00 00

    def getint(i,l=4): return int.from_bytes(header[i:i+l],byteorder="big",signed=False)
    
    self.data={}
    total=0  # total data length
    maxoff=0 # max data offset, should be (less or) equal to filesize
    pos=20
    for i in ["as","nd","nt","co","po"]:
        offset=getint(pos)
        length=getint(pos+4)
        if debug: print(i,offset,length)
        pos+=8
        total+=length
        if offset+length>maxoff: maxoff=offset+length
        f.seek(offset)
        self.data[i]=f.read(length)
#        if debug: print(self.data[i][:64])

    f.close()

    if debug:    
        print("Total data length:",total, maxoff)
        s1_length=getint(60,2)
        s2_length=getint(62,2)
        print("Signature lengths:",s1_length,s2_length)

    print("Vendor: ",self.getstr(getint(8)))
    print("Descr.: ",self.getstr(getint(12)))
    print("License:",self.getstr(getint(16)))

#    map_objects("co",8) # 2+2+4 bytes (code+continent+name)
#    map_objects("as",8) # 4+4 bytes   (Asnumber+name)
#    map_objects("nd",10) # 2+4+2+2    (country+asn+flags+padding)
#    map_objects("nt",12) # 4+4+4      (zero+one+net)

    if debug>1:
        pos=0
        maxnet=0
        while pos<len(self.data["nt"]):
            node=self.data["nt"][pos:pos+12]
            pos+=12
            net= int.from_bytes(node[8:12],byteorder="big",signed=True)
            if net>maxnet: maxnet=net
        netsize=len(self.data["nd"])/12
        print("max net: %d / %d"%(maxnet,netsize))

        pos=0
        while pos<len(self.data["as"]):
            node=self.data["as"][pos:pos+8]
            pos+=8
            asn=int.from_bytes(node[0:4],byteorder="big",signed=False)
            nid=int.from_bytes(node[4:8],byteorder="big",signed=False)
            print(asn,nid,self.getstr(nid))

  def getstr(self,i):
    s=self.data["po"][i:i+256] # max string len???
    j=s.find(b'\x00')
    return s[:j].decode("utf-8")

  def lookuptree(self,address,pos=0,level=0,debug=True):

    # return ((address->s6_addr[i / 8] >> (7 - (i % 8))) & 1);
    bit=(address[level//8] >> (7-(level&7)) )&1

#    bit=(address[level>>8]>>(level&7))&1
    node=self.data["nt"][pos*12:pos*12+12]

    zero=int.from_bytes(node[0:4],byteorder="big",signed=False)
    one= int.from_bytes(node[4:8],byteorder="big",signed=False)
    net= int.from_bytes(node[8:12],byteorder="big",signed=True)

#    print("level:",level,"pos:",pos,"bit:",bit,"next:",zero,one,"net:",net,"node:",node.hex(' '))
    if debug: print("level:",level,"pos:",pos,"bit:",bit,"next:",zero,one,"net:",net)

    nxt=one if bit else zero
    if nxt:
        # continue walking the tree...
        return self.lookuptree(address,nxt,level+1)
    return net

  def get_as(self, asfind):
    # FIXME: do binary search!
    pos=0
    while pos<len(self.data["as"]):
        node=self.data["as"][pos:pos+8]
        pos+=8
        asn=int.from_bytes(node[0:4],byteorder="big",signed=False)
        nid=int.from_bytes(node[4:8],byteorder="big",signed=False)
#        print(asn,nid,self.getstr(nid))
        if asn==asfind: return self.getstr(nid)
    return "N/A"

  def lookup(self, address):
    pos=self.lookuptree(address)
    if pos<0: return # not found
    node=self.data["nd"][pos*12:pos*12+12]
#    asn= int.from_bytes(node[2:6],byteorder="big",signed=False)
    asn=int.from_bytes(node[4:8],byteorder="big",signed=False)
    ass=self.get_as(asn)
    print(pos,node[0:2],asn,ass,node.hex(' '))


db=LocDB()

#addr=bytes([193,224,41,22])
#addr=bytes([0,0,0,0,0xFF,0xFF,0,0,  193,224,41,22])
#addr=bytes([0,0,0,0,  0,0,0,0,  0,0,0xFF,0xFF,  193,224,41,22])

#addr=bytes([0x2a,1,0x6e,0xe0, 0,1, 2,1,   0,0,0,0,0xB,0xAD,0xC0,0xDE])  # 2a01:6ee0:1:201::bad:c0de
#addr=bytes([0x2a,1,0xae,0x20, 8,1, 0x17,0x98,  0,0,0,0,0,0,0,1]) # 2a01:ae20:801:1798::1
addr=bytes([0x2a,2,7,0x30, 0x40,0, 0,0,  0,0,0,0,0,0,0,0xe0]) # 2a02:730:4000::e0

db.lookup(addr)

