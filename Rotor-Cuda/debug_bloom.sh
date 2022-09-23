rm obj/GPU/GPUEngine.o; make gpu=1 CCAP=61 all
# rm -rf Found.txt; ./Rotor -g --gpui 0 --gpux 1,1 -m addresses --coin eth --range 0:800 --in tc.bin  > Analysisgpu.txt; rm -rf Found.txt; ./Rotor -t 1 -m addresses --coin eth --range 0:800 --in tc.bin  > Analysiscpu.txt
rm -rf Found.txt; 
./Rotor -g --gpui 0 --gpux 1,1 -m addresses --coin eth --range 0:800 --in eth-sep.bin  > Analysisgpu.txt;
# rm -rf Found.txt; 
# ./Rotor -t 1 -m addresses --coin eth --range 0:800 --in eth-sep.bin > Analysiscpu.txt
