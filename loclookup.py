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

    def getstr(i):
        s=self.data["po"][i:i+256] # max string len???
        j=s.find(b'\x00')
        return s[:j].decode("utf-8")

    if debug:    
        print("Total data length:",total, maxoff)
        s1_length=getint(60,2)
        s2_length=getint(62,2)
        print("Signature lengths:",s1_length,s2_length)

    print("Vendor: ",getstr(getint(8)))
    print("Descr.: ",getstr(getint(12)))
    print("License:",getstr(getint(16)))



db=LocDB()

