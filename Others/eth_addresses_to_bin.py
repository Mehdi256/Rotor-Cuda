import sys


def eth_addresses_to_bin(filein, fileout):
    with open(filein) as inf, open(fileout, 'wb') as outf:
        count = 0
        skip = 0
        for x in inf:
            x = x.strip()
            x = x.split()[0]
            if len(x) != 40:
                skip += 1
                print("skipped address, len:", x)
                continue
            try:
                outf.write(bytes.fromhex(x))
                count += 1
            except:
                skip += 1
                print("skipped address, fromhex:", x)

        print('processed :', count, 'addresses', '\nskipped   :', skip, 'addresses', )


argc = len(sys.argv)
argv = sys.argv

if argc == 1 or argc != 3:
    print('Usage:')
    print('\tpython3 ' + argv[0].replace('\\', '/').split('/')[-1] + ' eth_addresses_in.txt eth_addresses_out.bin')
elif argc == 3:
    eth_addresses_to_bin(argv[1], argv[2])
