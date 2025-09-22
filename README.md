# Rotor-Cuda  v2.0
![alt text](Linux.jpg "Rotor-Cuda")

This is a modified version of KeyHunt v1.7 ... 
A lot of gratitude to all the developers whose codes has been used here  
Also, many thanks to the friends who allowed the Rotor-Cuda version 2 to be built and tested on their servers.

Telegram  **https://t.me/CryptoCrackersUK**

## Changes :
- Default Random 95% (252-256) bit + 5% (248-252) bit
- Random in a given bit range (1-256)
- Random between given bit ranges -n ? -z ?
- Random between the specified special for Puzzle --range 400000000:7ffffffff
- Time until the end of the search [years days hours minutes seconds] (max 300 years)
- Parameter -d 0 expert mode min. information (good for many GPUs)
- Automatic creation of Rotor-Cuda_START.bat with the specified cmd parameters 
- Continuation of the search in the range, from the last checkpoint 
- Ability to specify the time in minutes saving checkpoints 
- Many small visual improvements

### To scan in (GPUs)
- **-n ?** save checkpoint every ? minutes. (1-10000)
- If you do not specify -n ? (search without continuing) 
- After the Rotor-Cuda_Continue.bat file appears, you can continue from the last checkpoint.
- To continue correctly, do not change the parameters inside the file.
- **If you do not need to continue, DELETE the Rotor-Cuda_Continue.bat !!!** 
---
### For Random use - r 5 (GPUs)
- **-r ?** When you enter -r 5, it means that up to 5 billion keys are allowed to be scanned and after that, randomly selected sections will be scanned
- **-n ?** (1-256) bit. If you do not specify -n will be the default 95% (252-256) bit + 5% (248-252) bit
- **-z ?** (end random range must be greater than -n value) example: -n 252 -z 256
- Random for search [puzzle](https://privatekeys.pw/puzzles/bitcoin-puzzle-tx) 71 example:

- ```./Rotor -g --gpui 0 --gpux 256,256 -m address --coin BTC -r 5 --range 400000000000000000:7fffffffffffffffff 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU```
- If you know that your parameters are correct, use the expert mode -d 0 If you are using many GPUs use -d 0 for convenience 
- If your GPU is weaker than RTX 1080 or the driver crashes. Remove **--gpux 256,256** from the row the grid will be auto-assigned
---
### GPU Bitcoin Multi Address mode :
- Range: ```./Rotor -g --gpui 0 --gpux 256,256 -m addresses --coin BTC --range 400000000:7ffffffff -i Btc-h160.bin```
- Random: ```./Rotor -g --gpui 0 --gpux 256,256 -m addresses --coin BTC -r 5 -i Btc-h160.bin```
---
### GPU Bitcoin Single Addres mode :
- Range: ```./Rotor -g --gpui 0 --gpux 256,256 -m address --coin BTC --range 400000000:7ffffffff 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
- Random: ```./Rotor -g --gpui 0 --gpux 256,256 -m address --coin BTC --range 400000000:7ffffffff -r 5 1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb```
---
### GPU ETHEREUM Multi Address mode :
- Range: ```./Rotor -g --gpui 0 --gpux 256,256 -m addresses --coin eth --range 400000000:7ffffffff -i eth.bin```
- Random: ```./Rotor -g --gpui 0 --gpux 256,256 -m addresses --coin eth -r 5 -i eth.bin```
---
### GPU ETHEREUM Single Addres mode :
- Range: ```./Rotor -g --gpui 0 --gpux 256,256 -m address --coin eth --range 8000000:fffffff 0xfda5c442e76a95f96c09782f1a15d3b58e32404f```
- Random: ```./Rotor -g --gpui 0 --gpux 256,256 -m address --coin eth --range 8000000:fffffff -r 5 0xfda5c442e76a95f96c09782f1a15d3b58e32404f```


| GPU card |   Speed   |Grid Size|
|----------|:---------:|---------|
| Tesla T4 | 600 Mkeys | 128×256 |
| RTX 3090 |  2 Gkeys  | 256×256 |
| RTX 4090 |  3 Gkeys  | 256×512 |
| RTX 5090 |  5 Gkeys  | 512×512 |
| RTX 6090 |  ? Guess  |   x.y   |
