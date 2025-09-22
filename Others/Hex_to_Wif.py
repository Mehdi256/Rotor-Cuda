
import binascii, hashlib, base58, sys
arq = open('WIFS', 'w')

def convert(z):
    # Step 1: get the privatekey in extended format, this is hexadecimal upper or lower case.
    private_key_static = z
    # Step 2: adding 80 in the front for select de MAINNET channel bitcoin address
    extended_key = "80"+private_key_static
    # Step 3: first process SHA-256
    first_sha256 = hashlib.sha256(binascii.unhexlify(extended_key)).hexdigest()
    # Step 4: second process SHA-256
    second_sha256 = hashlib.sha256(binascii.unhexlify(first_sha256)).hexdigest()
    # Step 5-6: add checksum info to end of extended key
    final_key = extended_key+second_sha256[:8]
    # Step 7: finally the Wallet Import Format (WIF) is generated in the format base 58 encode of final_key
    WIF = base58.b58encode(binascii.unhexlify(final_key))
    # Step 8: show the private key on usual format WIF for wallet import. Enjoy!
    print ("Private Key on WIF format below")
    print (WIF)
    arq.write("\n" % WIF)

with open("hex.txt") as file:
    for line in file:
        print()
        convert(str.strip(line))

print ()