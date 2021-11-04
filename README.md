# Rotor-Cuda v1.04
![alt text](Others/Rotor-Cuda.jpg "Rotor-Cuda")
This is a modified version of KeyHunt v1.7 by [kanhavishva](https://github.com/kanhavishva/KeyHunt-Cuda).
A lot of gratitude to all the developers whose codes has been used here.

## Changes:
- Valid (sha256) bit random 95% (252-256) bit + 5% (248-252) bit
- Random in a given bit range
- Random between given bit ranges
- Random between the specified hashes ex: 8000000000:ffffffffff
- Time until the end of the search [years days hours minutes] (max 300 years)
- Parameter -d 0 expert mode min. information (good for several GPUs)
- Automatic creation of Rotor-Cuda_START.bat with the specified cmd parameters 
- Continuation of the search in the range, from the last checkpoint 
- Ability to specify the time in minutes saving checkpoints 
- Many small visual improvements

### To search in a Range (CPUs)
- **-t ?** how many cpu cores to use? (1-128 max)
- Add parameter -n 7 to save checkpoint every 7 minutes. (1-1000)
- If you do not specify -n ? (it will be a normal search without continuing) 
- After the Rotor-Cuda_Continue.bat file appears, you can continue from the last checkpoint.
- To continue correctly, do not change the parameters inside the file.
- **If you do not need to continue, delete the Rotor-Cuda_Continue.bat** 
- Example: Checkpoin recording every 2 minutes: 
- ```Rotor-Cuda.exe -t 6 -m address --coin BTC --range 400000000:7ffffffff 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb -n 2```

### Random (CPUs)
- **-t ?** how many cpu cores to use? (1-128 max)
- **-r ?** How many billions values to update starting Private Keys? (1-100)
- Specify the -n ? (1-256) bit range in which you want to generate private keys.
- -n 1 (Range: 1 - 256 (bit)) -n 2 Range: 120 - 256 (bit) -n 3 Range: 160 - 256 (bit) -n 4 Range: 200 - 256 (bit)
- Further -n (5-256) bit by bit. If you do not specify -n will be the default 95% (252-256) bit + 5% (248-252) bit
- Use -z (end random range must be greater than -n value) example: -n 253 -z 254 or pazles -n 63 -n 64 (8000000000000000:FFFFFFFFFFFFFFFF)
- Example: Random only in the 253rd range: 
- Random: ```Rotor-Cuda.exe -t 6 -m address --coin BTC -r 1 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb -n 253```
- Example: Random between 253 and 254 bit range:
- Random: ```Rotor-Cuda.exe -t 6 -m address --coin BTC -r 1 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb -n 253 -z 254```
- Random between private keys:
- ```Rotor-Cuda.exe -t 6 -m address --coin BTC --range 80000000:9000000 -r 1 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
- [**How to create databases**](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/) and [**additional parameters**](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Help.md)
### CPU Bitcoin Multi Address mode:
- Range: ```Rotor-Cuda.exe -t 1 -m addresses --coin BTC --range 1:1fffffffff -i puzzle_1_37_hash160_out_sorted.bin```
- Random: ```Rotor-Cuda.exe -t 1 -m addresses --coin BTC -r 1 -i base160sorted.bin```
---
### CPU Bitcoin Single Addres mode:
- Range: ```Rotor-Cuda.exe -t 1 -m address --coin BTC --range 400000000:7ffffffff 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
- Random: ```Rotor-Cuda.exe -t 1 -m address --coin BTC -r 1 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
---
### CPU ETHEREUM Multi Address mode:
- Range: ```Rotor-Cuda.exe -t 1 -m addresses --coin eth --range 1:1fffffffff -i puzzle_1_37_addresses_eth_sorted.bin```
- Random: ```Rotor-Cuda.exe -t 1 -m addresses --coin eth -r 1 -i base160_eth_sorted.bin```
---
### CPU ETHEREUM Single Addres mode:
- Range: ```Rotor-Cuda.exe -t 1 -m address --coin eth --range 8000000:fffffff 0xfda5c442e76a95f96c09782f1a15d3b58e32404f```
- Random: ```Rotor-Cuda.exe -t 1 -m address --coin eth -r 1 0xfda5c442e76a95f96c09782f1a15d3b58e32404f```
---
### CPU Public keys Multi X Points mode:
- Range: ```Rotor-Cuda.exe -t 1 -m xpoints --coin BTC --range 1:1fffffffff -i xpoints_1_37_out_sorted.bin```
- Random: ```Rotor-Cuda.exe -t 1 -m xpoints --coin BTC -r 1 -i Pubkeys0.1up.bin```
---
### CPU Public key Single X Point mode:
- Range: ```Rotor-Cuda.exe -t 1 -m xpoint --coin BTC --range 8000000000:ffffffffff a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4```
- Random: ```Rotor-Cuda.exe -t 1 -m xpoint --coin BTC -r 1 a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4```
---
### Example range mode -n 2 (6 cores):
```
C:\Users\user>Rotor-Cuda.exe -t 6 -m addresses --coin BTC --range 1000000:fffffffffffff -i all.bin -n 2

  Rotor-Cuda v1.04 (04.11.2021)

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Multi Address
  DEVICE       : CPU
  CPU THREAD   : 6
  SSE          : YES
  BTC HASH160s : all.bin
  OUTPUT FILE  : Found.txt

  Loading      : 100 %
  Loaded       : 32,892,770 Bitcoin addresses

  Bloom at     : 000001A693A09020
  Version      : 2.1
  Entries      : 65785540
  Error        : 0.0000010000
  Bits         : 1891674723
  Bits/Elem    : 28.755175
  Bytes        : 236459341 (225 MB)
  Hash funcs   : 20

  Site         : https://github.com/phrutis/Rotor-Cuda
  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  Start Time   : Thu Nov  4 21:43:40 2021
  Global start : 0000000000000000000000000000000000000000000000000000000001000000 (25 bit)
  Global end   : 000000000000000000000000000000000000000000000000000FFFFFFFFFFFFF (52 bit)
  Global range : 000000000000000000000000000000000000000000000000000FFFFFFEFFFFFF (52 bit)

  Rotor info   : Divide the range FFFFFFEFFFFFF (52 bit) into CPU 6 cores for fast parallel search


  Rotor info   : Save checkpoints every 2 minutes. For continue range, run the bat file Rotor-Cuda_Continue.bat
  CPU Core (2) : 0000000000000000000000000000000000000000000000000000000001000000 -> 0000000000000000000000000000000000000000000000000000000001000000
  CPU Core (2) : 0000000000000000000000000000000000000000000000000002AAAAAB7FFFFF -> 0000000000000000000000000000000000000000000000000002AAAAAB7FFFFF
  CPU Core (3) : 0000000000000000000000000000000000000000000000000005555555FFFFFE -> 0000000000000000000000000000000000000000000000000005555555FFFFFE
  CPU Core (4) : 00000000000000000000000000000000000000000000000000080000007FFFFD -> 00000000000000000000000000000000000000000000000000080000007FFFFD
  CPU Core (5) : 000000000000000000000000000000000000000000000000000AAAAAAAFFFFFC -> 000000000000000000000000000000000000000000000000000AAAAAAAFFFFFC
  CPU Core (6) : 000000000000000000000000000000000000000000000000000D5555557FFFFB -> 000000000000000000000000000000000000000000000000000FFFFFFFFFFFFF

  [00:00:53] [000000000000000000000000000000000000000000000000000000001CC44121] [F: 0] [C: 0.000011 %] [CPU 6: 8.87 Mk/s] [T: 481,603,584] [Years:016 Days:035 06:26:39]
```

### Continuation from Rotor-Cuda_Continue.bat
```
Rotor-Cuda v1.03 (02.11.2021)

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Multi Address
  DEVICE       : CPU
  CPU THREAD   : 6
  SSE          : YES
  BTC HASH160s : all.bin
  OUTPUT FILE  : Found.txt

  Loading      : 100 %
  Loaded       : 32,892,770 Bitcoin addresses

  Bloom at     : 00000225B07B9D60
  Version      : 2.1
  Entries      : 65785540
  Error        : 0.0000010000
  Bits         : 1891674723
  Bits/Elem    : 28.755175
  Bytes        : 236459341 (225 MB)
  Hash funcs   : 20

  Site         : https://github.com/phrutis/Rotor-Cuda
  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  Start Time   : Tue Nov  2 22:34:23 2021
  Rotor        : Continuing search from BAT file. Checkpoint created: Tue Nov  2 22:32:49 2021

  Global start : 0000000000000000000000000000000000000000000000000000000001000000 (25 bit)
  Global end   : 000000000000000000000000000000000000000000000000000FFFFFFFFFFFFF (52 bit)
  Global range : 000000000000000000000000000000000000000000000000000FFFFFFEFFFFFF (52 bit)

  Rotor info   : Continuation... Divide the remaining range FFFFEC1340FF9 (52 bit) into CPU 6 cores


  Rotor info   : Save checkpoints every 2 minutes. For continue range, run the bat file Rotor-Cuda_Continue.bat
  CPU Core (1) : 000000000000000000000000000000000000000000000000000555558AF752A8 -> 00000000000000000000000000000000000000000000000000080000357752A7
  CPU Core (2) : 0000000000000000000000000000000000000000000000000000000035F752AA -> 0000000000000000000000000000000000000000000000000002AAAAE07752A9
  CPU Core (3) : 0000000000000000000000000000000000000000000000000002AAAAE07752A9 -> 000000000000000000000000000000000000000000000000000555558AF752A8
  CPU Core (4) : 00000000000000000000000000000000000000000000000000080000357752A7 -> 000000000000000000000000000000000000000000000000000AAAAADFF752A6
  CPU Core (5) : 000000000000000000000000000000000000000000000000000D55558A7752A5 -> 0000000000000000000000000000000000000000000000000010000034F752A4
  CPU Core (6) : 000000000000000000000000000000000000000000000000000AAAAADFF752A6 -> 000000000000000000000000000000000000000000000000000FFFFFFFFFFFFF

  [00:00:17] [0000000000000000000000000000000000000000000000000000000140BFC03B] [F: 0] [C: 0.000123 %] [CPU 6: 10.93 Mk/s] [T: 5,526,210,560]
```

### Example Random mode use -n 253 -z 254 (6 cores):
```
C:\Users\user>Rotor-Cuda.exe -t 6 -m addresses --coin BTC -i all.bin -r 1 -n 253 -z 254

  Rotor-Cuda v1.04 (04.11.2021)

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Multi Address
  DEVICE       : CPU
  CPU THREAD   : 6
  SSE          : YES
  BTC HASH160s : all.bin
  OUTPUT FILE  : Found.txt

  Loading      : 100 %
  Loaded       : 32,892,770 Bitcoin addresses

  Bloom at     : 0000026FC31F6A00
  Version      : 2.1
  Entries      : 65785540
  Error        : 0.0000010000
  Bits         : 1891674723
  Bits/Elem    : 28.755175
  Bytes        : 236459341 (225 MB)
  Hash funcs   : 20

  Site         : https://github.com/phrutis/Rotor-Cuda
  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  Start Time   : Thu Nov  4 21:47:35 2021


  ROTOR Random : Private keys random 253 <~> 254 (bit)
  Range        : 1000000000000000000000000000000000000000000000000000000000000000 <~> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  Base Key     : Randomly changes 6 Private keys every 1,000,000,000 on the counter

  [00:04:31] [R: 2] [2DCE63F791F9F1D1EDC6226D04FA72789C3B92E34EC454F449E5F224D238F2B4] [F: 0] [CPU 6: 8.52 Mk/s] [T: 2,317,266,944]
 ```

### To search in a Range (GPUs)
- Add parameter -n 7 to save checkpoint every 7 minutes. (1-1000)
- If you do not specify -n ? (it will be a normal search without continuing) 
- After the Rotor-Cuda_Continue.bat file appears, you can continue from the last checkpoint.
- To continue correctly, do not change the parameters inside the file.
- **If you do not need to continue, delete the Rotor-Cuda_Continue.bat** 
---
### For Random (GPUs)
- **-r ?** How many billions to update 65535 starting Private Keys? (1-100000) Recommended every 5-15 minutes. (-n 250) 
- Specify the -n ? (1-256) bit range in which you want to generate private keys.
- -n 1 (Range: 1 - 256 (bit)) -n 2 Range: 120 - 256 (bit) -n 3 Range: 160 - 256 (bit) -n 4 Range: 200 - 256 (bit)
- Further -n (5-256) bit by bit. If you do not specify -n will be the default 95% (252-256) bit + 5% (248-252) bit
- Use -z (end random range must be greater than -n value) example: -n 253 -z 254 or pazles -n 63 -z 64 (8000000000000000:FFFFFFFFFFFFFFFF)
- Random between private keys:
- ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m address --coin BTC -r 100 --range 800000000:900000000 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
- If you know that your parameters are correct, use the expert mode -d 0 If you are using multiple GPUs use -d 0 for convenience 
- If your GPU is weaker than RTX 1080 or the driver crashes. Remove **--gpux 256,256** from the row the grid will be auto-assigned.
- [**How to create databases**](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/) and [**additional parameters**](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Help.md)
---
### GPU Bitcoin Multi Address mode:
- Range: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m addresses --coin BTC --range 1:1fffffffff -i puzzle_1_37_hash160_out_sorted.bin```
- Random: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m addresses --coin BTC -r 250 -i base160sorted.bin```
---
### GPU Bitcoin Single Addres mode:
- Range: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m address --coin BTC --range 400000000:7ffffffff 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
- Random: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m address --coin BTC -r 250 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
---
### GPU ETHEREUM Multi Address mode:
- Range: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m addresses --coin eth --range 1:1fffffffff -i puzzle_1_37_addresses_eth_sorted.bin```
- Random: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m addresses --coin eth -r 250 -i base160_eth_sorted.bin```
---
### GPU ETHEREUM Single Addres mode:
- Range: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m address --coin eth --range 8000000:fffffff 0xfda5c442e76a95f96c09782f1a15d3b58e32404f```
- Random: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m address --coin eth -r 250 0xfda5c442e76a95f96c09782f1a15d3b58e32404f```
---
### GPU Public key Multi X Points mode:
- Range: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoints --coin BTC --range 1:1fffffffff -i xpoints_1_37_out_sorted.bin```
- Random: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoints --coin BTC -r 250 -i Pubkeys1up.bin```
--- 
### GPU Public key Single X Point mode:
- Range: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoint --coin BTC --range 8000000000:ffffffffff a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4```
- Random: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoint --coin BTC -r 250 a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4```
- [**How to create databases**](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/) and [**additional parameters**](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Help.md)
---
### Example Range mode and -n 2:
```
C:\Users\user>Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoint --coin BTC --range 8000000000:ffffffffff a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4 -n 2

  Rotor-Cuda v1.04 (04.11.2021)

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Single X Point
  DEVICE       : GPU
  CPU THREAD   : 0
  GPU IDS      : 0
  GPU GRIDSIZE : 256x256
  SSE          : NO
  BTC XPOINT   : a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4
  OUTPUT FILE  : Found.txt

  Start Time   : Thu Nov  4 22:05:53 2021
  Global start : 0000000000000000000000000000000000000000000000000000008000000000 (40 bit)
  Global end   : 000000000000000000000000000000000000000000000000000000FFFFFFFFFF (40 bit)
  Global range : 0000000000000000000000000000000000000000000000000000007FFFFFFFFF (39 bit)

  GPU          : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(256x256)
  Rotor info   : Save checkpoints every 2 minutes. For continue range, run the bat file Rotor-Cuda_Continue.bat

  Rotor info   : Divide the range 7FFFFFFFFF (39 bit) into GPU 65536 threads

  Thread 00000 : 0000000000000000000000000000000000000000000000000000008000000000 -> 00000000000000000000000000000000000000000000000000000080007FFFFF
  Thread 00001 : 00000000000000000000000000000000000000000000000000000080007FFFFF -> 0000000000000000000000000000000000000000000000000000008000FFFFFE
  Thread 00002 : 0000000000000000000000000000000000000000000000000000008000FFFFFE -> 00000000000000000000000000000000000000000000000000000080017FFFFD
  Thread 00003 : 00000000000000000000000000000000000000000000000000000080017FFFFD -> 0000000000000000000000000000000000000000000000000000008001FFFFFC
           ... :
  Thread 65534 : 000000000000000000000000000000000000000000000000000000FFFEFF0002 -> 000000000000000000000000000000000000000000000000000000FFFF7F0001
  Thread 65535 : 000000000000000000000000000000000000000000000000000000FFFF7F0001 -> 000000000000000000000000000000000000000000000000000000FFFFFF0000
  Thread 65536 : 000000000000000000000000000000000000000000000000000000FFFFFF0000 -> 00000000000000000000000000000000000000000000000000000100007EFFFF

  [00:02:50] [000000000000000000000000000000000000000000000000000000C9CACC51B0] [F: 0] [C: 57.812500 %] [GPU: 1.87 Gk/s] [T: 317,827,579,904] [Time left: 00:02:03]
  =================================================================================
  PubAddress: 1EeAxcprB2PpCnr34VfZdFrkUWuxyiNEFv
  Priv (WIF): p2pkh:KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9aFJuCJDo5F6Jm7
  Priv (HEX): E9AE4933D6
  PubK (HEX): 03A2EFA402FD5268400C77C20E574BA86409EDEDEE7C4020E4B9F0EDBEE53DE0D4
  =================================================================================
  [00:02:51] [000000000000000000000000000000000000000000000000000000CA3A864EC1] [F: 1] [C: 58.154297 %] [GPU: 1.87 Gk/s] [T: 319,706,628,096] [Time left: 00:02:02]

  BYE
```

### Continuation (example above) from last checkpoint run Rotor-Cuda_Continue.bat
```
C:\Users\user>Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoint --coin BTC --range 8000000000:ffffffffff a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4 -n 2

  Rotor-Cuda v1.04 (04.11.2021)

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Single X Point
  DEVICE       : GPU
  CPU THREAD   : 0
  GPU IDS      : 0
  GPU GRIDSIZE : 256x256
  SSE          : NO
  BTC XPOINT   : a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4
  OUTPUT FILE  : Found.txt

  Start Time   : Thu Nov  4 22:09:46 2021
  Rotor        : Continuing search from BAT file. Checkpoint created: Thu Nov  4 22:07:47 2021

  Global start : 0000000000000000000000000000000000000000000000000000008000000000 (40 bit)
  Global end   : 000000000000000000000000000000000000000000000000000000FFFFFFFFFF (40 bit)
  Global range : 0000000000000000000000000000000000000000000000000000007FFFFFFFFF (39 bit)

  GPU          : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(256x256)
  Rotor info   : Save checkpoints every 2 minutes. For continue range, run the bat file Rotor-Cuda_Continue.bat

  Rotor info   : Continuation... Divide the remaining range 4FC7FFFFFF (39 bit) into GPU 65536 threads

  Thread 00000 : 0000000000000000000000000000000000000000000000000000008000303800 -> 00000000000000000000000000000000000000000000000000000080007FFFFF
  Thread 00001 : 0000000000000000000000000000000000000000000000000000008000B037FF -> 0000000000000000000000000000000000000000000000000000008000FFFFFE
  Thread 00002 : 00000000000000000000000000000000000000000000000000000080013037FE -> 00000000000000000000000000000000000000000000000000000080017FFFFD
  Thread 00003 : 0000000000000000000000000000000000000000000000000000008001B037FD -> 0000000000000000000000000000000000000000000000000000008001FFFFFC
           ... :
  Thread 65534 : 000000000000000000000000000000000000000000000000000000FFFF2F3802 -> 000000000000000000000000000000000000000000000000000000FFFF7F0001
  Thread 65535 : 000000000000000000000000000000000000000000000000000000FFFFAF3801 -> 000000000000000000000000000000000000000000000000000000FFFFFF0000
  Thread 65536 : 00000000000000000000000000000000000000000000000000000100002F3800 -> 00000000000000000000000000000000000000000000000000000100007EFFFF

  [00:00:55] [000000000000000000000000000000000000000000000000000000C4F1DD06C2] [F: 0] [C: 57.617188 %] [GPU: 1.92 Gk/s] [T: 316,753,838,080] [Time left: 00:02:01]   8:88]
  =================================================================================
  PubAddress: 1EeAxcprB2PpCnr34VfZdFrkUWuxyiNEFv
  Priv (WIF): p2pkh:KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9aFJuCJDo5F6Jm7
  Priv (HEX): E9AE4933D6
  PubK (HEX): 03A2EFA402FD5268400C77C20E574BA86409EDEDEE7C4020E4B9F0EDBEE53DE0D4
  =================================================================================
  [00:00:56] [000000000000000000000000000000000000000000000000000000C56490EB33] [F: 1] [C: 57.958984 %] [GPU: 1.92 Gk/s] [T: 318,632,886,272] [Time left: 00:02:00]

  BYE

C:\Users\user>goto :loop
```

### Example Random mode use -n 63 -z 64:
```
C:\Users\user>Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoint --coin BTC -r 50 a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4 -n 63 -z 64

  Rotor-Cuda v1.04 (04.11.2021)

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Single X Point
  DEVICE       : GPU
  CPU THREAD   : 0
  GPU IDS      : 0
  GPU GRIDSIZE : 256x256
  SSE          : NO
  BTC XPOINT   : a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4
  OUTPUT FILE  : Found.txt

  Start Time   : Thu Nov  4 22:12:37 2021

  GPU          : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(256x256)
  ROTOR Random : Private keys random 63 <~> 64 (bit) Range: 8000000000000000 <~> FFFFFFFFFFFFFFFF
  Base Key     : Randomly changes 65536 start Private keys every 50,000,000,000 on the counter

  [00:01:17] [R: 2] [000000000000000000000000000000000000000000000000ACF1BCC81C962052] [F: 0] [GPU: 2.07 Gk/s] [T: 141,868,138,496]
```
### Example Random --range
```
C:\Users\user>Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoints --coin BTC -r 100 --range 7777777777:8888888888 -i Pub01.bin

  Rotor-Cuda v1.04 (04.11.2021)

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Multi X Points
  DEVICE       : GPU
  CPU THREAD   : 0
  GPU IDS      : 0
  GPU GRIDSIZE : 256x256
  SSE          : NO
  BTC XPOINTS  : Pub01.bin
  OUTPUT FILE  : Found.txt

  Loading      : 100 %
  Loaded       : 243,734 Bitcoin xpoints

  Bloom at     : 00000202CA1375B0
  Version      : 2.1
  Entries      : 487468
  Error        : 0.0000010000
  Bits         : 14017227
  Bits/Elem    : 28.755175
  Bytes        : 1752154 (1 MB)
  Hash funcs   : 20

  Site         : https://github.com/phrutis/Rotor-Cuda
  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  Start Time   : Thu Nov  4 22:17:25 2021

  GPU          : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(256x256)
  Base Key     : Randomly changes 65536 start Private keys every 100,000,000,000 on the counter

  ROTOR Random : Private keys random in Range: 7777777777 <~> 8888888888 (MAX)

  [00:02:45] [R: 2] [0000000000000000000000000000000000000000000000000000007207A8C063] [F: 0] [GPU: 1.34 Gk/s] [T: 217,566,937,088]
```
### Example for multiple GPUs range search parameter -d 0
```
C:\Users\user>Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m address --coin eth --range 1:1fffffffffffffff -d 0 0xfda5c442e76a95f96c09782f1a15d3b58e32404f

  Rotor-Cuda v1.04 (04.11.2021)

  COIN TYPE    : ETHEREUM
  SEARCH MODE  : Single Address
  DEVICE       : GPU
  CPU THREAD   : 0
  GPU IDS      : 0
  GPU GRIDSIZE : 256x256
  SSE          : NO
  ETH ADDRESS  : 0xfda5c442e76a95f96c09782f1a15d3b58e32404f
  OUTPUT FILE  : Found.txt

  Start Time   : Thu Nov  4 22:39:14 2021

  GPU          : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(256x256)
  [00:01:28] [F: 0] [C: 0.000002 %] [GPU: 485.26 Mk/s] [T: 42,547,019,776] [Years:150 Days:247 05:02:02]
```
## Building
### Windows
- Microsoft Visual Studio Community 2019
- CUDA version [**10.22**](https://developer.nvidia.com/cuda-10.2-download-archive?target_os=Windows&target_arch=x86_64&target_version=10&target_type=exenetwork)
## License
- Rotor-Cuda is licensed under GPLv3.

## Donation
- BTC: bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

## __Disclaimer__
ALL THE CODES, PROGRAM AND INFORMATION ARE FOR EDUCATIONAL PURPOSES ONLY. USE IT AT YOUR OWN RISK. THE DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY LOSS, DAMAGE OR CLAIM ARISING FROM USING THIS PROGRAM.

