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
- For the test, you can use a ready-made base puzzle_1_37_hash160_out_sorted.bin

## How to create a base of Ethereum addresses 

- Downloading the fresh database of ethereum addresses [here](https://blockchair.com/dumps)
- Use Python: ```python eth_addresses_to_bin.py eth_addresses_in.txt eth_addresses_out.bin```
- Next, you need to sort the base eth_addresses_out.bin
- CMD: ```BinSort.exe 20 eth_addresses_out.bin eth_addresses_sotrted.bin```
- Or another program CMD: ```RMD160-Sort.exe eth_addresses_out.bin eth_addresses_sorted.bin```
- For the test, you can use a ready-made base puzzle_1_37_addresses_eth_sorted.bin

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
- For the test, you can use a ready-made base xpoints_1_37_out_sorted.bin
---
- It takes a long time to get public addresses from the blockchain. 
- It took me a week to get all public keys from [1 BTC up](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys1up.txt). It will take a month to get from [0.1 BTC up](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys0.1up.txt).
- There are 2 text files with public keys in the others folder. 
- In the others folder there are 2 files ([Pubkeys1up.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys1up.bin) and [Pubkeys0.1up.bin](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Pubkeys0.1up.bin)) with ready-made bin databases for Multi X Points mode. 
- **Good luck in finding**  
