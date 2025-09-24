## How to create a File with the".bin" extension
- Add Address File ( BTC or ETH ) to BinSort Folder 
- Rename the files to ( if ETH ) ETH_addresses.txt """" ( if BTC ) BTC_addresses.txt
- ~ cd BinSort 
  
  ```sh

  sudo apt install -y libgmp-dev
    
  sudo pip3 install base58
    
  make

    ```
- To convert files ( BTC or ETH.txt ) to h160 : 

      python3 BTC_addr_to_hash160.py BTC_addresses.txt hash160_out.bin
      
      python3 ETH_addresses_to_bin.py ETH_addresses.txt ETH_out.bin 

    Outputs ==> hash160_out.bin  ''''''''  ETH_out.bin

- To convert files ( out.bin ) to sorted files 

      ./BinSort 20 hash160_out.bin BTC_h160.bin

      ./BinSort 20 ETH_out.bin ETH_sort.bin

- Now move Files **BTC_h160.bin**  or  **ETH_sort.bin** to Rotor-Cuda Folder

## Good luck
   
