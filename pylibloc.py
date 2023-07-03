#! /usr/bin/python3

class LocDB:
  def __init__(self,fn="/var/lib/location/database.db",debug=2):

    if fn.endswith(".xz"):
        import lzma
        f=lzma.open(fn,"rb")
    else:
        f=open(fn,"rb")

    magic=f.read(8)    # 7 bytes magic + 1 byte version
    if debug: print(magic[0:7],magic[7])
    if magic!=b'LOCDBXX\x01': raise Exception("Unknown database format!")

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
    
    self.asncache={}

    # find root node for mapped IPv4 lookups:  [0000:0000:0000:0000:0000:FFFF:xxxx:xxxx/96]
    nxt=0
    for i in range(10*8): nxt=int.from_bytes(self.data["nt"][nxt*12:nxt*12+4],byteorder="big",signed=False)
    for i in range(2*8):  nxt=int.from_bytes(self.data["nt"][nxt*12+4:nxt*12+8],byteorder="big",signed=False)
    self.v4root=nxt
    if debug: print("IPv4 root node:",nxt)

    # map cc codes to dict for faster lookup:   (only 254 codes!)
    self.cc_dict={}
    pos=0
    while pos<len(self.data["co"]):
        key=self.data["co"][pos:pos+2]
        cont=self.data["co"][pos+2:pos+4]      # continent code (2 ascii chars)
        nid=int.from_bytes(self.data["co"][pos+4:pos+8],byteorder="big",signed=False)
        self.cc_dict[key]=( key.decode(), cont.decode(), self.getstr(nid) )
        pos+=8
    if debug: print("Country-codes found:",len(self.cc_dict))

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
        maxasn=0
        maxnid=0
        while pos<len(self.data["as"]):
            node=self.data["as"][pos:pos+8]
            pos+=8
            asn=int.from_bytes(node[0:4],byteorder="big",signed=False)
            nid=int.from_bytes(node[4:8],byteorder="big",signed=False)
            if asn>maxasn: maxasn=asn
            if nid>maxnid: maxnid=nid
#            print(asn,nid,self.getstr(nid))
        # ASN: 96997 entries, max asn=401308  max nid=1694094
        print("ASN: %d entries, max asn=%d  max nid=%d"%(len(self.data["as"])//8,maxasn,maxnid))

  def getstr(self,i):
    s=self.data["po"][i:i+256] # max string len???
    j=s.find(b'\x00')
    return s[:j].decode("utf-8")

  def get_as(self, asfind):
    if asfind in self.asncache: return self.getstr(self.asncache[asfind])
    p1,p2=0,len(self.data["as"])//8
    while p1<p2:
        pos=(p1+p2)//2  # do binary search!  avg 15 steps/lookup
        x=int.from_bytes(self.data["as"][pos*8:pos*8+4],byteorder="big",signed=False)
        if asfind==x:
            nid=int.from_bytes(self.data["as"][pos*8+4:pos*8+8],byteorder="big",signed=False)
            self.asncache[asfind]=nid
            return self.getstr(nid)
        if asfind>x: p1=pos+1
        else: p2=pos
    return "N/A"

  def lookuptree(self,address,map4=False,debug=False):
    nxt=self.v4root if map4 else 0
    ret=(-1,0)
    mask=0
    while mask<len(address)*8:
      bit=(address[mask//8] >> (7-(mask&7)) )&1
      node=self.data["nt"][nxt*12:nxt*12+12]
      net=int.from_bytes(node[8:12],byteorder="big",signed=True)
      if debug:
        zero=int.from_bytes(node[0:4],byteorder="big",signed=False)
        one= int.from_bytes(node[4:8],byteorder="big",signed=False)
        print("mask:",mask,"pos:",nxt,"bit:",bit,"next:",zero,one,"net:",net)
      if net>=0: ret=(net,mask)
      nxt=int.from_bytes(node[4*bit:4*bit+4],byteorder="big",signed=False)
      if nxt==0: break
      mask+=1
    return ret

  # IPv4-optimized version of generic lookuptree,  len(address) must be 4 bytes (32 bits)
  def lookuptree4(self,address):
    data=self.data["nt"]
    nxt=12*self.v4root
    ret=(-1,0)
    ip=int.from_bytes(address,byteorder="big",signed=False)
    mask=0
    while mask<32:
#      net=(data[nxt+8]<<24)|(data[nxt+9]<<16)|(data[nxt+10]<<8)|data[nxt+11]
      net=int.from_bytes(data[nxt+8:nxt+12],byteorder="big",signed=True)
      if net>=0: ret=(net,mask)
      bit=(ip>>29)&4  # == 4*((ip>>31)&1)
      nxt=12*int.from_bytes(data[nxt+bit:nxt+bit+4],byteorder="big",signed=False)
      if nxt==0: break
      mask+=1
      ip<<=1
    return ret

  def lookup6(self, address, map4=False):
    pos,mask=self.lookuptree4(address) if map4 else self.lookuptree(address)
#    pos,mask=self.lookuptree(address,map4)
    if pos<0: return # not found
    node=self.data["nd"][pos*12:pos*12+12] # network data: countrycode(2) + padding(2) + ASN(4) + flags(2) +padding(2)
    co=node[0:2] # country code
    asn=int.from_bytes(node[4:8],byteorder="big",signed=False)
    flags=int.from_bytes(node[8:10],byteorder="big",signed=False)
    ass=self.get_as(asn) # AS: string from number
    cos=self.cc_dict.get(co,None)  # Country code, continent code & country name
    # print(pos,node[0:2],asn,ass,node.hex(' '))
    return cos,asn,ass,flags,mask

  def lookup4(self, address):
    return self.lookup6(address,True)

  def lookup(self, addrstr):
    from ipaddress import ip_address
    address=ip_address(addrstr).packed # string -> bytes
    return self.lookup6(address, len(address)==4)

if __name__ == "__main__":

  db=LocDB("location.db.xz")

  import sys
  if len(sys.argv)>1:
    for ip in sys.argv[1:]: print(db.lookup(ip))
  else:
    print(db.lookup4(bytes([193,224,41,22])))
#    exit(0)
    print(db.lookup6(bytes([0x2a,1,0x6e,0xe0, 0,1, 2,1,   0,0,0,0,0xB,0xAD,0xC0,0xDE])))
    print(db.lookup("1.1.1.1"))
    print(db.lookup("2a00:1450:400d:806::2005"))
    
    import time
    t0=time.time()
    cimek=[]
    from ipaddress import ip_address
    for line in open("v46cimek2","rt"):
        address=ip_address(line.strip()).packed
#        if len(address)==16:
        cimek.append(address) # string -> bytes
    print("Load time: %d ms"%(1000.0*(time.time()-t0)))

#    t0=time.time()
    for address in cimek:
#        pos,mask=db.lookuptree(address,db.v4root if len(address)==4 else 0)
        res=db.lookup6(address, len(address)==4)
#        if not res: print("%d.%d.%d.%d"%(address[0],address[1],address[2],address[3]))
    t0=time.time()-t0
    print("Lookup time: %d ms  avg: %5.3f ns/ip (%d total)"%(1000.0*t0, 1000000.0*t0/len(cimek), len(cimek) ))
#    print(len(db.asncache)) # 7681
    