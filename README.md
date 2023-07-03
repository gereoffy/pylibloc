# pylibloc - Pure python libloc (location.db) implementation

libloc is a maxmind-GeoIP alternative to lookup IPv4/IPv6 address geo-location.

Also look at my minimal C implementation here:  https://github.com/gereoffy/ipstat46/blob/main/nanolibloc.c

Get database from:
- https://location.ipfire.org/databases/1/location.db.xz

Done:
- open database (even from xz file) and check magic
- load database headers & data (in linear order)
- IPv4 & IPv6 address lookup (from bytes or string format)
- speed optimization! using pypy it's 2x faster than original libloc py binding...
- no redundant v4->v6 addr conversions, no recursive binary tree traversal...

TODO:
- maybe a better API...

Benchmark:  (lookup of all the 500k+ unique addresses from file 'v46cimek2')
- original libloc py-binding (python3.10):  1385 ms
- my code running by pypy (3.10): 564 ms !!!
- my code running by python3.10: 3650 ms
- my code running by python3.11: 3074 ms  (pure python only ~2x slower than libloc C code)


Usage:

    db=LocDB("location.db.xz")
    print(db.lookup4(bytes([193,224,41,22])))
    print(db.lookup6(bytes([0x2a,1,0x6e,0xe0, 0,1, 2,1,   0,0,0,0,0xB,0xAD,0xC0,0xDE])))
    print(db.lookup("1.1.1.1"))
    print(db.lookup("2a00:1450:400d:806::2005"))
    
output:  
(('HU', 'EU', 'Hungary'), 1955, 'KIFU (Governmental Info Tech Development Agency)', 0, 15)  
(('HU', 'EU', 'Hungary'), 62214, 'Rackforest Zrt.', 0, 40)  
(('AU', 'OC', 'Australia'), 13335, 'CLOUDFLARENET', 4, 24)  
(('IE', 'EU', 'Ireland'), 15169, 'GOOGLE', 0, 48)

