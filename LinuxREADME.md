## Linux building

1. Install libgmp-dev
2. Install CUDA 11.7
 
 - Or pass them as variables to `make` command.
 - Install libgmp: ```sudo apt install -y libgmp-dev```


    ```make
    CUDA       = /usr/local/cuda-11.7
    CXXCUDA    = /usr/bin/g++
    ```
 - To build CPU-only version (without CUDA support):
    ```sh
    $ make all
    ```
 - To build with CUDA: pass CCAP value according to your GPU compute capability
    ```sh
    $ cd Rotor-Cuda
    $ make gpu=1 CCAP=75 all
    $ make gpu=1 CCAP=85 all
    ```
    <hr>
    FOR RTX 3060, 3070, 3080, 3090, A5000, A6000, A100 - use CCAP=75 (CUDA 11.7)</br>
    FOR RTX 2070, 2080 - use CCAP=75 (CUDA 11.7)</br>
    FOR GTX 1060, 1070, 1080 - use CCAP=61 (CUDA 10.2)</br>

```
LD_LIBRARY_PATH=/home/Eric_Vader/.conda/envs/rotor/lib ./Rotor -t 1 -m address --coin eth -r 1 0xfda5c442e76a95f96c09782f1a15d3b58e32404f
LD_LIBRARY_PATH=/home/Eric_Vader/.conda/envs/rotor/lib ./Rotor -g --gpui 0 --gpux 256,256 -m address --coin eth -r 250 0xfda5c442e76a95f96c09782f1a15d3b58e32404f
LD_LIBRARY_PATH=/home/Eric_Vader/.conda/envs/rotor/lib ./Rotor -g -m address --coin eth -r 250 0xfda5c442e76a95f96c09782f1a15d3b58e32404f
LD_LIBRARY_PATH=/home/Eric_Vader/.conda/envs/rotor/lib ./Rotor -g -m address --coin eth --range 800000000:fffffffff 0x1ffbb8f1dfc7e2308c39637e3f4b63c2362ddc6c
LD_LIBRARY_PATH=/home/Eric_Vader/.conda/envs/rotor/lib ./Rotor -t 12 -m address --coin eth --range AAAAAAAAA:AAfffffff 0x1ffbb8f1dfc7e2308c39637e3f4b63c2362ddc6c
LD_LIBRARY_PATH=/home/Eric_Vader/.conda/envs/rotor/lib ./Rotor -g --gpui 0 --gpux 32,32 -m address --coin eth --range AAAAAAAAA:AAfffffff 0x1ffbb8f1dfc7e2308c39637e3f4b63c2362ddc6c
LD_LIBRARY_PATH=/home/Eric_Vader/.conda/envs/rotor/lib ./Rotor -t 32 -m address --coin eth --range 0:10000 0x8928729d215e3c145fd4577407e2D53da4353aD1
```

g++ obj/Base58.o obj/IntGroup.o obj/Main.o obj/Bloom.o obj/Random.o obj/Sort.o obj/Timer.o obj/Int.o obj/IntMod.o obj/Point.o obj/SECP256K1.o obj/Rotor.o obj/GPU/GPUGenerate.o obj/hash/ripemd160.o obj/hash/sha256.o obj/hash/sha512.o obj/hash/ripemd160_sse.o obj/hash/sha256_sse.o obj/hash/keccak160.o obj/GPU/GPUEngine.o obj/GmpUtil.o obj/CmdParse.o -lgmp -lpthread -L/home/Eric_Vader/.conda/envs/rotor/lib -lcudart -o Rotor


```
python eth_addresses_to_bin.py accounts.tsv eth_addresses_out.bin
./RMD160-Sort eth_addresses_out.bin eth_addresses_outs.bin
LD_LIBRARY_PATH=/home/Eric_Vader/.conda/envs/rotor/lib ./Rotor -g -m addresses --coin eth --range 0:100000000 --in ./eth_addresses_outs.bin
./Rotor -t 12 -m addresses --coin eth --range 0:100000000 --in ./eth_addresses_outs.bin
```