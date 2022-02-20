# python-bof-runner
Python inline shellcode injector that could be used to run BOFs by leveraging BOF2shellcode

Python can be used to run Cobalt Strike's BOFs by using previous work from [Trustedsec](https://github.com/trustedsec/COFFLoader) and [FalconForce](https://medium.com/falconforce/bof2shellcode-a-tutorial-converting-a-stand-alone-bof-loader-into-shellcode-6369aa518548), one can pick a BOF and use [BOF2Shellcode](https://github.com/FalconForceTeam/BOF2shellcode) to embed the shellcode in a python injector.

## HowTo

1. clone bof2shellcode

2. grab an x64 BOF

3. create the shellcode blob containing the converted BOF and COFFloader:

`python3  ./BOF2shellcode/bof2shellcode.py -i ./bofs/tasklist.x64.o -o ./scodes/tasklist.x64.bin`

4. make tasklist.x64.bin easily pastable:

`msfvenom -p generic/custom PAYLOADFILE=tasklist.x64.bin -f python > sc_tasklist.txt`

5. paste she shellcode in the injector and update the code accordingly


## Demo

![](https://github.com/naksyn/python-bof-runner/blob/main/bof-runner.gif)
