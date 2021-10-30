# Rotor-Cuda v1.02

This is a modified version of KeyHunt v1.7 by [kanhavishva](https://github.com/kanhavishva/KeyHunt-Cuda).
A lot of gratitude to all the developers whose codes has been used here.

## Changes:
- Made a valid bit random 95% (252-256) bit + 5% (248-252) bit
- Many small visual improvements
### CPU Options: 
- **-t ?** how many cpu cores to use? (1-128 max) 
- **-r ?** How many billions to update starting Private Keys? (1-100)
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
### CPU Public key Single X Point mode:
- Range: ```Rotor-Cuda.exe -t 1 -m xpoint --coin BTC --range 8000000000:ffffffffff a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4```
- Random: ```Rotor-Cuda.exe -t 1 -m xpoint --coin BTC -r 1 a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4```

### Example range mode (6 cores):
```
C:\Users\user>Rotor-Cuda.exe -t 6 -m addresses --coin BTC --range 1000000:fffffffffffff -i all.bin

  Rotor-Cuda v1.02

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

  Bloom at     : 0000027791DF8CB0
  Version      : 2.1
  Entries      : 65785540
  Error        : 0.0000010000
  Bits         : 1891674723
  Bits/Elem    : 28.755175
  Bytes        : 236459341 (225 MB)
  Hash funcs   : 20

  Site         : https://github.com/phrutis/Rotor-Cuda
  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  Start Time   : Sat Oct 30 23:23:20 2021
  Global start : 1000000 (25 bit)
  Global end   : FFFFFFFFFFFFF (52 bit)
  Global range : FFFFFFEFFFFFF (52 bit)


  CPU Core     : Start from range 1000000 ->
  CPU Core     : Start from range 2AAAAAB7FFFFF ->
  CPU Core     : Start from range 5555555FFFFFE ->
  CPU Core     : Start from range 80000007FFFFD ->
  CPU Core     : Start from range D5555557FFFFB ->
  CPU Core     : Start from range AAAAAAAFFFFFC ->
  [00:00:32] [12251B1F] [F: 0] [C: 0.000006 %] [CPU 6: 8.76 Mk/s] [T: 285,118,464]
```
---
### Example Random mode (6 cores):
```
C:\Users\user>Rotor-Cuda.exe -t 6 -m addresses --coin BTC -i all.bin -r 1

  Rotor-Cuda v1.02

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

  Bloom at     : 000001F9755C8FC0
  Version      : 2.1
  Entries      : 65785540
  Error        : 0.0000010000
  Bits         : 1891674723
  Bits/Elem    : 28.755175
  Bytes        : 236459341 (225 MB)
  Hash funcs   : 20

  Site         : https://github.com/phrutis/Rotor-Cuda
  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  Start Time   : Sat Oct 30 23:24:59 2021


  Base Key     : Randomly changes 6 Private keys every 1.000.000.000 on the counter

  [00:00:42] [R: 0] [328C57FA645C45EC54003742A8B59CA191A9DB0510E16200765C16A59C86AA94] [F: 0] [CPU 6: 8.67 Mk/s] [T: 370,978,816]
 ```

### GPU Options: 
- **-r ?** How many billions to update 65535 starting Private Keys? (1-100000) Recommended every 5-15 minutes. (-n 250) 
- If your GPU is weaker than RTX 1080 or the driver crashes. Remove **--gpux 256,256** from the row the grid will be auto-assigned.
- [**How to create databases**](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/) and [**additional parameters**](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Help.md)
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
### Example Range mode:
```
C:\Users\user>Rotor-Cuda.exe -g --gpui 0 --gpux 288,512 -m xpoint --coin BTC --range 8000000000:ffffffffff a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4

  Rotor-Cuda v1.02

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Single X Point
  DEVICE       : GPU
  CPU THREAD   : 0
  GPU IDS      : 0
  GPU GRIDSIZE : 288x512
  SSE          : NO
  BTC XPOINT   : a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4
  OUTPUT FILE  : Found.txt

  Start Time   : Sat Oct 30 23:27:45 2021
  Global start : 8000000000 (40 bit)
  Global end   : FFFFFFFFFF (40 bit)
  Global range : 7FFFFFFFFF (39 bit)

  GPU          : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(288x512)
  Divide the range 7FFFFFFFFF into 147456 threads for fast parallel search
  Thread 00000: 0000000000000000000000000000000000000000000000000000008000000000 -> 000000000000000000000000000000000000000000000000000000800038E38E
  Thread 00001: 000000000000000000000000000000000000000000000000000000800038E38E -> 000000000000000000000000000000000000000000000000000000800071C71C
  Thread 00002: 000000000000000000000000000000000000000000000000000000800071C71C -> 0000000000000000000000000000000000000000000000000000008000AAAAAA
  Thread 00003: 0000000000000000000000000000000000000000000000000000008000AAAAAA -> 0000000000000000000000000000000000000000000000000000008000E38E38
          ... :
  Thread 147454: 000000000000000000000000000000000000000000000000000000FFFF8DB8E4 -> 000000000000000000000000000000000000000000000000000000FFFFC69C72
  Thread 147455: 000000000000000000000000000000000000000000000000000000FFFFC69C72 -> 000000000000000000000000000000000000000000000000000000FFFFFF8000
  Thread 147456: 000000000000000000000000000000000000000000000000000000FFFFFF8000 -> 000000000000000000000000000000000000000000000000000001000038638E

  [00:01:20] [253087D675] [F: 0] [C: 28.948975 %] [GPU: 1.96 Gk/s] [T: 159,148,670,976]
  =================================================================================
  PubAddress: 1EeAxcprB2PpCnr34VfZdFrkUWuxyiNEFv
  Priv (WIF): p2pkh:KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9aFJuCJDo5F6Jm7
  Priv (HEX): E9AE4933D6
  PubK (HEX): 03A2EFA402FD5268400C77C20E574BA86409EDEDEE7C4020E4B9F0EDBEE53DE0D4
  =================================================================================
  [00:01:22] [2619E9C237] [F: 1] [C: 29.663086 %] [GPU: 1.96 Gk/s] [T: 163,074,539,520]

  BYE

```
---
### Example Random mode:
```
C:\Users\user>Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoint --coin BTC -r 50 a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4

  Rotor-Cuda v1.02

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

  Start Time   : Sat Oct 30 22:44:36 2021

  GPU          : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(256x256)
  Base Key     : Randomly changes 65536 start Private keys every 50.000.000.000 on the counter

  [00:00:50] [R: 1] [AC6B20DFFBAAE5025980E5582C31331D01B64FA1C9A988CAC0FFFF6922459314] [F: 0] [GPU: 1.99 Gk/s] [T: 93,012,885,504]
```

## Building
##### Windows
- Microsoft Visual Studio Community 2019
- CUDA version [**10.22**](https://developer.nvidia.com/cuda-10.2-download-archive?target_os=Windows&target_arch=x86_64&target_version=10&target_type=exenetwork)
## License
- Rotor-Cuda is licensed under GPLv3.

## Donation
- BTC: bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

## __Disclaimer__
ALL THE CODES, PROGRAM AND INFORMATION ARE FOR EDUCATIONAL PURPOSES ONLY. USE IT AT YOUR OWN RISK. THE DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY LOSS, DAMAGE OR CLAIM ARISING FROM USING THIS PROGRAM.

