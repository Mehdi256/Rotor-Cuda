:loop 
Rotor-Cuda.exe -g --gpui 0 --gpux 320,128 -m addresses --coin BTC --range 20:1ffffff -r 1 -i hex160sorted.bin 
goto :loop 

