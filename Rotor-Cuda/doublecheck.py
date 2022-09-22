
priv_dict = {}
with open("tc.txt") as found_file:
    for ea_line in found_file:
        addr_str, priv_key_str = ea_line.strip().split('\t')
        addr = bytes.fromhex(addr_str[2:])
        priv_key = int(f"0x{priv_key_str.strip()}", 16)
        if priv_key in priv_dict:
            print(priv_key_str)
        priv_dict[priv_key] = addr
        # print(f"./Rotor -g --gpui 0 --gpux 128,128 -m address --coin eth --range 0:100000000 {addr_str}")

sorted_addrs = [ priv_dict[priv_key] for priv_key in sorted(priv_dict.keys()) ]

with open("tc.bin", 'wb') as tc_file:
    for addr in sorted(sorted_addrs):
        tc_file.write(addr)

addrs_set = set(sorted_addrs)

to_check_addrs_set = set()
with open("Found.txt") as found_file:
    for ea_line in found_file:
        addr_str, priv_key_str = ea_line.strip().split('\t')
        addr = bytes.fromhex(addr_str[2:])
        to_check_addrs_set.add(addr)

print(addrs_set - to_check_addrs_set)
print(to_check_addrs_set - addrs_set)