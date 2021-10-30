# Rotor-Cuda v1.01

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
- Random: ```Rotor-Cuda.exe -t 1 -m addresses --coin BTC -r 1 -i test.bin```
---
### CPU Bitcoin Single Addres mode:
- Range: ```Rotor-Cuda.exe -t 1 -m address --coin BTC --range 400000000:7ffffffff 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
- Random: ```Rotor-Cuda.exe -t 1 -m address --coin BTC -r 1 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
---
### CPU ETHEREUM Multi Address mode:
- Range: ```Rotor-Cuda.exe -t 1 -m addresses --coin eth --range 1:1fffffffff -i puzzle_1_37_addresses_eth_sorted.bin```
- Random: ```Rotor-Cuda.exe -t 1 -m addresses --coin eth -r 1 -i base160_eth.bin```
---
### CPU ETHEREUM Single Addres mode:
- Range: ```Rotor-Cuda.exe -t 1 -m address --coin eth --range 8000000:fffffff 0xfda5c442e76a95f96c09782f1a15d3b58e32404f```
- Random: ```Rotor-Cuda.exe -t 1 -m address --coin eth -r 1 0xfda5c442e76a95f96c09782f1a15d3b58e32404f```
---
### CPU Public keys Multi X Points mode:
- Range: ```Rotor-Cuda.exe -t 1 -m xpoints --coin BTC --range 1:1fffffffff -i xpoints_1_37_out_sorted.bin```
- Random: ```Rotor-Cuda.exe -t 1 -m xpoints --coin BTC -r 1 -i basex.bin```
### CPU Public key Single X Point mode:
- Range: ```Rotor-Cuda.exe -t 1 -m xpoint --coin BTC --range 8000000000:ffffffffff a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4```
- Random: ```Rotor-Cuda.exe -t 1 -m xpoint --coin BTC -r 1 a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4```

### Example range mode (6 cores):
```
C:\Users\user>Rotor-Cuda.exe -t 6 -m addresses --coin BTC --range 1000000:fffffffffffff -i test.bin

  Rotor-Cuda v1.01

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Multi Address
  DEVICE       : CPU
  CPU THREAD   : 6
  SSE          : YES
  MAX FOUND    : 65536
  BTC HASH160s : test.bin
  OUTPUT FILE  : Found.txt

  Loading      : 100 %
  Loaded       : 75,471 Bitcoin addresses

  Bloom at     : 0000021805729750
  Version      : 2.1
  Entries      : 150942
  Error        : 0.0000010000
  Bits         : 4340363
  Bits/Elem    : 28.755175
  Bytes        : 542546 (0 MB)
  Hash funcs   : 20

  Site         : https://github.com/phrutis/Rotor-Cuda
  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  Start Time   : Tue Oct 26 20:11:40 2021
  Global start : 1000000 (25 bit)
  Global end   : FFFFFFFFFFFFF (52 bit)
  Global range : FFFFFFEFFFFFF (52 bit)


  CPU Core     : Start from range 1000000 ->
  CPU Core     : Start from range 2AAAAAB7FFFFF ->
  CPU Core     : Start from range 5555555FFFFFE ->
  CPU Core     : Start from range 80000007FFFFD ->
  CPU Core     : Start from range AAAAAAAFFFFFC ->
  CPU Core     : Start from range D5555557FFFFB ->
  [00:00:30] [E7EDFC4] [CPU+GPU: 7.36 Mk/s] [GPU: 0.00 Mk/s] [C: 0.000005 %] [T: 225,638,400 (28 bit)] [F: 0]
```
---
### Example Random mode (6 cores):
```
C:\Users\user>Rotor-Cuda.exe -t 6 -m addresses --coin BTC -i test.bin -r 1

  Rotor-Cuda v1.01

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Multi Address
  DEVICE       : CPU
  CPU THREAD   : 6
  SSE          : YES
  RKEY         : Reload every 1000000000
  MAX FOUND    : 65536
  BTC HASH160s : test.bin
  OUTPUT FILE  : Found.txt

  Loading      : 100 %
  Loaded       : 75,471 Bitcoin addresses

  Bloom at     : 000002727C9E8850
  Version      : 2.1
  Entries      : 150942
  Error        : 0.0000010000
  Bits         : 4340363
  Bits/Elem    : 28.755175
  Bytes        : 542546 (0 MB)
  Hash funcs   : 20

  Site         : https://github.com/phrutis/Rotor-Cuda
  Donate       : bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

  Start Time   : Tue Oct 26 19:58:20 2021


  Base Key     : Randomly changes 6 Private keys every 1.000.000.000 on the counter

  [00:06:55] [R: 3] [43B7AA48BA4FF45F3D711F1C64FBC049BB86A063A953C918414E0CDC72B7788D] [F: 0] [CPU+GPU: 7.33 Mk/s] [GPU: 0.00 Mk/s] [T: 3,088,900,096]
 ```

### GPU Options: 
- **-r ?** How many billions to update 65535 starting Private Keys? (1-100000) Recommended every 5-15 minutes. (-n 250) 
- If your GPU is weaker than RTX 1080 or the driver crashes. Remove **--gpux 256,256** from the row the grid will be auto-assigned.
- [**How to create databases**](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/) and [**additional parameters**](https://github.com/phrutis/Rotor-Cuda/blob/main/Others/Help.md)
### GPU Bitcoin Multi Address mode:
- Range: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m addresses --coin BTC --range 1:1fffffffff -i puzzle_1_37_hash160_out_sorted.bin```
- Random: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m addresses --coin BTC -r 250 -i test.bin```
---
### GPU Bitcoin Single Addres mode:
- Range: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m address --coin BTC --range 400000000:7ffffffff 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
- Random: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m address --coin BTC -r 250 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
---
### GPU ETHEREUM Multi Address mode:
- Range: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m addresses --coin eth --range 1:1fffffffff -i puzzle_1_37_addresses_eth_sorted.bin```
- Random: ```Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m addresses --coin eth -r 250 -i base160_eth.bin```
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
C:\Users\user>Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoint --coin BTC --range 1:fffffffffffffffff a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4

  Rotor-Cuda v1.01

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Single X Point
  DEVICE       : GPU
  CPU THREAD   : 0
  GPU IDS      : 0
  GPU GRIDSIZE : 256x256
  SSE          : NO
  MAX FOUND    : 65536
  BTC XPOINT   : a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4
  OUTPUT FILE  : Found.txt

  Start Time   : Tue Oct 26 20:47:27 2021
  Global start : 1 (1 bit)
  Global end   : FFFFFFFFFFFFFFFFF (68 bit)
  Global range : FFFFFFFFFFFFFFFFE (68 bit)

  GPU          : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(256x256)

  Divide the range FFFFFFFFFFFFFFFFE into 65536 threads for fast parallel search
  Thread 00000: 0000000000000000000000000000000000000000000000000000000000000001 -> 0000000000000000000000000000000000000000000000000010000000000000
  Thread 00001: 0000000000000000000000000000000000000000000000000010000000000000 -> 000000000000000000000000000000000000000000000000001FFFFFFFFFFFFF
  Thread 00002: 000000000000000000000000000000000000000000000000001FFFFFFFFFFFFF -> 000000000000000000000000000000000000000000000000002FFFFFFFFFFFFE
  Thread 00003: 000000000000000000000000000000000000000000000000002FFFFFFFFFFFFE -> 000000000000000000000000000000000000000000000000003FFFFFFFFFFFFD
          ... :
  Thread 65534: 00000000000000000000000000000000000000000000000FFFDFFFFFFFFF0003 -> 00000000000000000000000000000000000000000000000FFFEFFFFFFFFF0002
  Thread 65535: 00000000000000000000000000000000000000000000000FFFEFFFFFFFFF0002 -> 00000000000000000000000000000000000000000000000FFFFFFFFFFFFF0001
  Thread 65536: 00000000000000000000000000000000000000000000000FFFFFFFFFFFFF0001 -> 000000000000000000000000000000000000000000000010000FFFFFFFFF0000

  [00:01:49] [3047F25AB4] [CPU+GPU: 1.89 Gk/s] [GPU: 1.89 Gk/s] [C: 0.000000 %] [T: 209,111,220,224 (38 bit)] [F: 0]
```
---
### Example Random mode:
```
C:\Users\user>Rotor-Cuda.exe -g --gpui 0 --gpux 256,256 -m xpoint --coin BTC -r 250 a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4

  Rotor-Cuda v1.01

  COMP MODE    : COMPRESSED
  COIN TYPE    : BITCOIN
  SEARCH MODE  : Single X Point
  DEVICE       : GPU
  CPU THREAD   : 0
  GPU IDS      : 0
  GPU GRIDSIZE : 256x256
  SSE          : NO
  RKEY         : Reload every 250000000000
  MAX FOUND    : 65536
  BTC XPOINT   : a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4
  OUTPUT FILE  : Found.txt

  Start Time   : Tue Oct 26 20:53:07 2021

  GPU          : GPU #0 NVIDIA GeForce RTX 2070 (36x64 cores) Grid(256x256)

  Base Key     : Randomly changes 65536 start Private keys every 250.000.000.000 on the counter

  [00:05:19] [R: 2] [E15D8F8CFCA9E196B1B65C6B7F0B31BCCD4B8C1901DCF03F408DB5670D618ADD] [F: 0] [CPU+GPU: 1.93 Gk/s] [GPU: 1.93 Gk/s] [T: 568,814,731,264]
```

## Building
##### Windows
- Microsoft Visual Studio Community 2019
- CUDA version [**10.22**](https://developer.nvidia.com/cuda-10.2-download-archive?target_os=Windows&target_arch=x86_64&target_version=10&target_type=exenetwork)
## License
Rotor-Cuda is licensed under GPLv3.

## Donation
- BTC: bc1qh2mvnf5fujg93mwl8pe688yucaw9sflmwsukz9

## __Disclaimer__
ALL THE CODES, PROGRAM AND INFORMATION ARE FOR EDUCATIONAL PURPOSES ONLY. USE IT AT YOUR OWN RISK. THE DEVELOPER WILL NOT BE RESPONSIBLE FOR ANY LOSS, DAMAGE OR CLAIM ARISING FROM USING THIS PROGRAM.

