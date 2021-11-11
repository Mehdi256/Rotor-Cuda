## How to create a base of addresses 

- Downloading the fresh database of addresses [here](https://blockchair.com/dumps)
- We take Legacy addresses starting with 1xxx... from the base and create a list addresses.txt
- Converting addresses to RMD160 binary format:
- Install base58 ```python -m pip install base58```
- Use Python: ```python addresses_to_hash160.py addresses.txt hax160.bin```
- if there is no python Windows: ```b58dec.exe addresses.txt hex160.bin```
- Next, you need to sort the base hex160.bin
- CMD: ```BinSort.exe 20 hex160.bin hex160sorted.bin```
- Or another program CMD: ```RMD160-Sort.exe hex160.bin hex160sorted.bin```
- For the test, you can use a ready-made base [puzzle_1_37_hash160_out_sorted.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/puzzle_1_37_hash160_out_sorted.bin)

## How to create a base of Ethereum addresses 

- Downloading the fresh database of ethereum addresses [here](https://blockchair.com/dumps)
- Use Python: ```python eth_addresses_to_bin.py eth_addresses_in.txt eth_addresses_out.bin```
- Next, you need to sort the base eth_addresses_out.bin
- CMD: ```BinSort.exe 20 eth_addresses_out.bin eth_addresses_sotrted.bin```
- Or another program CMD: ```RMD160-Sort.exe eth_addresses_out.bin eth_addresses_sorted.bin```
- For the test, you can use a ready-made base [puzzle_1_37_addresses_eth_sorted.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/puzzle_1_37_addresses_eth_sorted.bin)

## How to create a base of Public keys for Multi X Points mode

- Downloading the fresh database of addresses [here](https://blockchair.com/dumps)
- We take Legacy addresses starting with 1xxx... from the base and create a list addresses.txt
- Use Python: ```Pub-from-blockchain.py``` (addresses.txt file is created pubkeys.txt) (speed limit 50 address in 60 sek)
- Or manually use the link [https://blockchain.info/q/pubkeyaddr/1P5ZEDWTKTFGxQjZphgWPQUpe554WKDfHQ](https://blockchain.info/q/pubkeyaddr/1P5ZEDWTKTFGxQjZphgWPQUpe554WKDfHQ)
- Since the search is compressed, public keys starting with 02 and 03 are suitable for it. 
- You can use public keys from Uncompressed addresses 04 (128 characters). The script converts them to a compressed format.
- If the program finds such a public key, it will give a compressed address. Using the found private key, generate a positive uncompressed address
- Convert public keys (02,03,04) use Python: ```python pubkeys_to_xpoint.py pubkeys_in.txt xpoints_out.bin```
- Make sure to sort the base CMD: ```BinSort.exe 32 xpoints_out.bin Xpoints_Sorted.bin```
- For the test, you can use a ready-made base [xpoints_1_37_out_sorted.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/xpoints_1_37_out_sorted.bin)
- Public keys for puzzles single use:
- **120** 17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT **02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630**
- **125** 1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5 **0233709EB11E0D4439A729F21C2C443DEDB727528229713F0065721BA8FA46F00E**
- **130** 1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua **03633CBE3EC02B9401C5EFFA144C5B4D22F87940259634858FC7E59B1C09937852**
- **135** 16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v **02145D2611C823A396EF6712CE0F712F09B9B4F3135E3E0AA3230FB9B6D08D1E16**
- **140** 1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo **031F6A332D3C5C4F2DE2378C012F429CD109BA07D69690C6C701B6BB87860D6640**
- **145** 19GpszRNUej5yYqxXoLnbZWKew3KdVLkXg **03AFDDA497369E219A2C1C369954A930E4D3740968E5E4352475BCFFCE3140DAE5**
- **150** 1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy **03137807790EA7DC6E97901C2BC87411F45ED74A5629315C4E4B03A0A102250C49**
- **155** 1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ **035CD1854CAE45391CA4EC428CC7E6C7D9984424B954209A8EEA197B9E364C05F6**
- **160** 1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv **02E0A8B039282FAF6FE0FD769CFBC4B6B4CF8758BA68220EAC420E32B91DDFA673**
---
- It takes a long time to get public addresses from the blockchain. 
- It took me a week to get all public keys from [1 BTC up](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys1up.txt). It will take a month to get from [0.1 BTC up](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys0.1up.txt).
- In the Others folder there are 2 files ([Pubkeys1up.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys1up.bin) and [Pubkeys0.1up.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys0.1up.bin)) with ready-made bin databases for Multi X Points mode. 
- **Good luck in finding**  
