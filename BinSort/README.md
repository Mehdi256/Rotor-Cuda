## How to create a file with the".bin" extension for BTC & ETH Multi Address Mode
- 1. Add Bitcoin and Ethereum_addresses.txt to BinSort Folder 
- 2. Rename the files to ETH_addresses.txt """" BTC_addresses.txt
- 3. ~ cd BinSort 
  
  ```sh

      sudo apt install -y libgmp-dev
    
      sudo pip3 install  base58
    
      make

    ```
- 4. To convert files ( BTC & ETH.txt ) to h160 : 

       python3  BTC_addr_to_hash160.py  BTC_addresses.txt  hash160_out.bin

       python3  ETH_addresses_to_bin.py  ETH_addresses.txt  ETH_out.bin 

       **Outputs**  ==>  hash160_out.bin  ''''''''  ETH_out.bin

- 5. To convert files ( out.bin ) to sorted files 

      ./BinSort  20  hash160_out.bin  BTC_h160.bin

      ./BinSort  20  ETH_out.bin  ETH_sort.bin

- 6. Now move Files **BTC_h160.bin** and **ETH_sort.bin** to Rotor-Cuda Folder

## Good luck
   
