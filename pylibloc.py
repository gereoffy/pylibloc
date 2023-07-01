#! /usr/bin/python3

class LocDB:
  def __init__(self,fn="/var/lib/location/database.db",debug=0):

    if fn.endswith(".xz"):
        import lzma
        f=lzma.open(fn,"rb")
    else:
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

    def getint(i,l=4): return int.from_bytes(header[i:i+l],byteorder="big",signed=False)

    # read data!
    blocks=sorted([ [getint(pos),getint(pos+4),i] for pos,i in [(20,"as"),(28,"nd"),(36,"nt"),(44,"co"),(52,"po")] ]) # data block positions
    self.data={}
    fpos=8+64
    for offset,length,i in blocks:
        if debug: print(i,offset,length,offset+length,offset-fpos)
        f.read(offset-fpos) #  f.seek(offset)
        self.data[i]=f.read(length)
        fpos=offset+length
    f.close()

    if debug:
        total=sum(b[1] for b in blocks)
        maxoff=max(b[0]+b[1] for b in blocks)
        print("Total data length:",total, maxoff)
        s1_length=getint(60,2)
        s2_length=getint(62,2)
        print("Signature lengths:",s1_length,s2_length)

    self.date=getint(0,8)
    self.vendor=self.getstr(getint(8))
    self.descr=self.getstr(getint(12))
    self.license=self.getstr(getint(16))


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

  def get_as(self, asfind):
    # FIXME: do binary search!
    pos=0
    while pos<len(self.data["as"]):
        if asfind==int.from_bytes(self.data["as"][pos:pos+4],byteorder="big",signed=False):
            nid=int.from_bytes(self.data["as"][pos+4:pos+8],byteorder="big",signed=False)
            return self.getstr(nid)
        pos+=8
    return "N/A"

  def get_cc(self, ccfind):
    pos=0
    while pos<len(self.data["co"]):
        if ccfind==self.data["co"][pos:pos+2]:     # (code+continent+name)
            cont=self.data["co"][pos+2:pos+4]      # continent code (2 ascii chars)
            nid=int.from_bytes(self.data["co"][pos+4:pos+8],byteorder="big",signed=False)
            return ccfind.decode(),cont.decode(),self.getstr(nid)
        pos+=8
    return None

  def lookuptree(self,address,pos=0,mask=0,debug=False):
    bit=(address[mask//8] >> (7-(mask&7)) )&1
    node=self.data["nt"][pos*12:pos*12+12]
    nxt=int.from_bytes(node[4*bit:4*bit+4],byteorder="big",signed=False)
    net=int.from_bytes(node[8:12],byteorder="big",signed=True)
    if debug:
        zero=int.from_bytes(node[0:4],byteorder="big",signed=False)
        one= int.from_bytes(node[4:8],byteorder="big",signed=False)
        print("mask:",mask,"pos:",pos,"bit:",bit,"next:",zero,one,"net:",net)
    if nxt and mask<len(address)*8:
        # continue walking the tree...
        net2,mask2=self.lookuptree(address,nxt,mask+1)
        if net2>=0: return net2,mask2
    return net,mask

  def lookup6(self, address, map4=False):
    if map4: address=bytes([0,0,0,0,  0,0,0,0,  0,0,0xFF,0xFF]) + address   # map IPv4 to IPv6
    pos,mask=self.lookuptree(address)
    if pos<0: return # not found
    node=self.data["nd"][pos*12:pos*12+12] # network data: countrycode(2) + padding(2) + ASN(4) + flags(2) +padding(2)
    co=node[0:2] # country code
    asn=int.from_bytes(node[4:8],byteorder="big",signed=False)
    flags=int.from_bytes(node[8:10],byteorder="big",signed=False)
    ass=self.get_as(asn) # AS: string from number
    cos=self.get_cc(co)  # Country code, continent code & country name
    # print(pos,node[0:2],asn,ass,node.hex(' '))
    return cos,asn,ass,flags,mask-12*8 if map4 else mask

  def lookup4(self, address):
    return self.lookup6(address,True)

  def lookup(self, addrstr):
    from ipaddress import ip_address
    address=ip_address(addrstr).packed # string -> bytes
    return self.lookup6(address, len(address)==4)

if __name__ == "__main__":

    db=LocDB("location.db.xz")
    print(db.lookup4(bytes([193,224,41,22])))
    print(db.lookup6(bytes([0x2a,1,0x6e,0xe0, 0,1, 2,1,   0,0,0,0,0xB,0xAD,0xC0,0xDE])))
    print(db.lookup("1.1.1.1"))
    print(db.lookup("2a00:1450:400d:806::2005"))

