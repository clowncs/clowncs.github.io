---
weight: 1
title: "amateursCTF 2024"
date: 2024-04-09T14:30:00+07:00
lastmod: 2024-04-09T14:30:00+07:00
draft: false
author: "ClownCS"
authorLink: "https://clowncs.github.io"
description: "Solutions for some reverse challenges in amateursCTF 2024"
tags: ["RE", "2024"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---
Solutions for some reverse challenges in amateursCTF 2024
<!--more-->
# RE
Reverse challenges in this event are fun so i want to keep some of them on my blog.

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/144ed917-d08a-4ada-975b-e7e9c7024748)

## typo
{{< admonition >}}
166 solves / 243 points

can you make sure i didn't make a typo?
{{< /admonition >}}

```python
import random as RrRrRrrrRrRRrrRRrRRrrRr
RrRrRrrrRrRRrrRRrRRrRrr = int('1665663c', 20)
RrRrRrrrRrRRrrRRrRRrrRr.seed(RrRrRrrrRrRRrrRRrRRrRrr)
arRRrrRRrRRrRRRrRrRRrRr = bytearray(open('flag.txt', 'rb').read())
arRRrrRrrRRrRRRrRrRRrRr = '\r'r'\r''r''\\r'r'\\r\r'r'r''r''\\r'r'r\r'r'r\\r''r'r'r''r''\\r'r'\\r\r'r'r''r''\\r'r'rr\r''\r''r''r\\'r'\r''\r''r\\\r'r'r\r''\rr'
arRRrrRRrRRrRrRrRrRRrRr = [
    b'arRRrrRRrRRrRRrRr',
    b'aRrRrrRRrRr',
    b'arRRrrRRrRRrRr',
    b'arRRrRrRRrRr',
    b'arRRrRRrRrrRRrRR'
    b'arRRrrRRrRRRrRRrRr',
    b'arRRrrRRrRRRrRr',
    b'arRRrrRRrRRRrRr'
    b'arRrRrRrRRRrrRrrrR',
]
arRRRrRRrRRrRRRrRrRRrRr = lambda aRrRrRrrrRrRRrrRRrRrrRr: bytearray([arRrrrRRrRRrRRRrRrRrrRr + 1 for arRrrrRRrRRrRRRrRrRrrRr in aRrRrRrrrRrRRrrRRrRrrRr])
arRRrrRRrRRrRRRrRrRrrRr = lambda aRrRrRrrrRrRRrrRRrRrrRr: bytearray([arRrrrRRrRRrRRRrRrRrrRr - 1 for arRrrrRRrRRrRRRrRrRrrRr in aRrRrRrrrRrRRrrRRrRrrRr])
def arRRrrRRrRRrRrRRrRrrRrRr(hex):
    for id in range(0, len(hex) - 1, 2):
        hex[id], hex[id + 1] = hex[id + 1], hex[id]
    for list in range(1, len(hex) - 1, 2):
        hex[list], hex[list + 1] = hex[list + 1], hex[list]
    return hex
arRRRRRRrRRrRRRrRrRrrRr = [arRRrrRRrRRrRrRRrRrrRrRr, arRRRrRRrRRrRRRrRrRRrRr, arRRrrRRrRRrRRRrRrRrrRr]
arRRRRRRrRRrRRRrRrRrrRr = [RrRrRrrrRrRRrrRRrRRrrRr.choice(arRRRRRRrRRrRRRrRrRrrRr) for arRrrrRRrRRrRRRrRrRrrRr in range(128)]
def RrRrRrrrRrRRrrRRrRRrrRr(arr, ar):
    for r in ar:
        arr = arRRRRRRrRRrRRRrRrRrrRr[r](arr)
    return arr
def arRRrrRRrRRrRrRRrRrrRrRr(arr, ar):
    ar = int(ar.hex(), 17)
    for r in arr:
        ar += int(r, 35)
    return bytes.fromhex(hex(ar)[2:])
arrRRrrrrRRrRRRrRrRRRRr = RrRrRrrrRrRRrrRRrRRrrRr(arRRrrRRrRRrRRRrRrRRrRr, arRRrrRrrRRrRRRrRrRRrRr.encode())
arrRRrrrrRRrRRRrRrRRRRr = arRRrrRRrRRrRrRRrRrrRrRr(arRRrrRRrRRrRrRrRrRRrRr, arrRRrrrrRRrRRRrRrRRRRr)
print(arrRRrrrrRRrRRRrRrRRRRr.hex())

# output: 5915f8ba06db0a50aa2f3eee4baef82e70be1a9ac80cb59e5b9cb15a15a7f7246604a5e456ad5324167411480f893f97e3
```

This challenge is just simply obfuscate the code so we can deobfuscate by hand and test each function until it's correct. This is my friend's  ([s1gm4](https://s19ma.github.io/)) script:

```python
import random as Random_Module
Random_Seed = int('1665663c', 20)
Random_Module.seed(Random_Seed)
Random_part1 = '\r'r'\r''r''\\r'r'\\r\r'r'r''r''\\r'r'r\r'r'r\\r''r'r'r''r''\\r'r'\\r\r'r'r''r''\\r'r'rr\r''\r''r''r\\'r'\r''\r''r\\\r'r'r\r''\rr'
Random_part2 = [
    b'arRRrrRRrRRrRRrRr',
    b'aRrRrrRRrRr',
    b'arRRrrRRrRRrRr',
    b'arRRrRrRRrRr',
    b'arRRrRRrRrrRRrRR'
    b'arRRrrRRrRRRrRRrRr',
    b'arRRrrRRrRRRrRr',
    b'arRRrrRRrRRRrRr'
    b'arRrRrRrRRRrrRrrrR',
]
inv_funcion1 = lambda something: bytearray([val - 1 for val in something])
inv_funcion2 = lambda something: bytearray([val + 1 for val in something])

def funcion3(hex):
    for id in range(0, len(hex) - 1, 2):
        hex[id], hex[id + 1] = hex[id + 1], hex[id]
    for list in range(1, len(hex) - 1, 2):
        hex[list], hex[list + 1] = hex[list + 1], hex[list]
    return hex

def inv_funcion3(hex):
    for list in range(1, len(hex) - 1, 2):
        hex[list+1], hex[list] = hex[list], hex[list+1]
    for id in range(0, len(hex) - 1, 2):
        hex[id+1], hex[id] = hex[id], hex[id+1]

    return hex

list_func_inv = [inv_funcion3, inv_funcion1, inv_funcion2]
list_func_inv = [Random_Module.choice(list_func_inv) for val in range(128)]

def Random_Module_choice(arr, ar):
    for r in ar:
        arr = list_func_inv[r](arr)
        print(arr)
    return arr

def inv_function3_(arr, ar):
    ar = int(ar, 16)
    for r in arr:
        ar -= int(r, 35)

    return ar

flag_enc = "5915f8ba06db0a50aa2f3eee4baef82e70be1a9ac80cb59e5b9cb15a15a7f7246604a5e456ad5324167411480f893f97e3"
flagg = inv_function3_(Random_part2, flag_enc) 
flaggg = "486f67686960685561685568552559536660375b3a5d28625353275d676753595c6029275a712858536067602b646167" 
fl = bytearray(bytes.fromhex(flaggg))
flag_enc = Random_Module_choice(fl, Random_part1.encode())
print(flag_enc)
```
Flag: ***amateursCTF{4t_l3ast_th15_fl4g_isn7_misspelll3d}***

## cplusplus
{{< admonition >}}
37 solves / 386 points

idk why everyone keeps telling me to use c++? c is just as good.
{{< /admonition >}}
Actually, when I read the title of this challenge, I recognize it is a meme on [reddit](https://www.reddit.com/r/programminghorror/comments/18x7vk9/why_does_everyone_keep_telling_me_to_use_c/). Maybe the challenge is related to that meme? Download the file and open it with IDA, this is a few things we can see.

```C
unsigned __int64 __fastcall stage_1(unsigned __int64 a1, unsigned __int64 a2)
{
  unsigned __int64 i; // [rsp+18h] [rbp-8h]

  for ( i = 0LL; i < a2; i = s1(i) )
    a1 = s1(a1);
  return a1 % qword_4010;
}
__int64 __fastcall stage_2(__int64 a1, __int64 a2)
{
  return s2(a1, a2, 0LL, stage_1);
}
__int64 __fastcall stage_3(__int64 a1, __int64 a2)
{
  return s2(a1, a2, 1LL, stage_2);
}
unsigned __int64 __fastcall s2(
        unsigned __int64 a1,
        unsigned __int64 a2,
        unsigned __int64 a3,
        __int64 (__fastcall *a4)(unsigned __int64, unsigned __int64))
{
  while ( a2 )
  {
    if ( (a2 & 1) != 0 )
      a3 = a4(a3, a1) % (unsigned __int64)qword_4010;
    a1 = a4(a1, a1) % (unsigned __int64)qword_4010;
    a2 >>= 1;
  }
  return a3;
}
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  unsigned __int64 v6; // [rsp+0h] [rbp-70h]
  __int64 i; // [rsp+8h] [rbp-68h]
  FILE *stream; // [rsp+10h] [rbp-60h]
  char ptr[2]; // [rsp+1Eh] [rbp-52h] BYREF
  char s[72]; // [rsp+20h] [rbp-50h] BYREF
  unsigned __int64 v11; // [rsp+68h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  fgets(s, 64, stdin);
  stream = fopen("/dev/urandom", "r");
  fread(ptr, 1uLL, 2uLL, stream);
  fclose(stream);
  v6 = 0LL;
  for ( i = 0LL; s[i]; ++i )
  {
    v3 = stage_1(v6, s[i]);
    v4 = stage_2(v3, (unsigned __int8)ptr[0]);
    v6 = stage_3(v4, (unsigned __int8)ptr[1]);
    if ( i )
      printf(", ");
    printf("%zu", v6);
  }
  putchar(10);
  return 0LL;
}
```

As you can see, the program simply takes 2 bytes randomly and then transforms your input through 3 stages and then prints. But the problem is this program is not optimized so it runs slow as fuck. Because of that, we need to optimize to get the flag. After debugging and reading the code, I know that ``stage_1`` is just adding two parameters and ``stage_2`` is multiplying two parameters 💀. This is enough to run so I don't change stage_3 anymore. Optimizing is done but one more important thing is we need to know 2 bytes randomly in order to generate the right number. Bruteforcing and we get this ``0xed, 0x29``. My final optimized code and solution:

```C
#include <stdio.h>

size_t stage_2(size_t stage1, size_t random, size_t a3) {
    return (stage1 * random) % 0x3B9ACA07;
}
size_t stage3(size_t stage2, size_t random, size_t a3) {
    while (random) {
        if (random & 1)
            a3 = stage_2(a3, stage2, 0) % 0x3B9ACA07;
        stage2 = stage_2(stage2, stage2, 0) % 0x3B9ACA07;
        random >>= 1;
    }
    return a3;
}

int main() {
size_t flag[] = {816696039, 862511530, 897431439, 341060728, 173157153, 31974957, 491987052, 513290022, 463763452, 949994705, 910803499, 303483511, 378099927, 773435663, 305463445, 656532801, 655150297, 28357806, 69914739, 213536453, 962912446, 458779691, 598643891, 94970179, 732507398, 792930123, 216371336, 680163935, 397010125, 693248832, 926462193, 419350956, 594922380, 944019434, 93600641, 116339550, 373995190, 558908218, 700841647, 703877327, 665247438, 690373754, 35138387, 389900716, 625740467, 682452898, 894528752, 603308386, 442640217, 15961938, 573068354};
printf("a");
for (int i = 1; i < sizeof(flag);i++){
    for (int j = 32; j < 126; j++){
        size_t tmp = 0;
        size_t v3 = stage_2(j + flag[i-1], 0xed, 0);
        tmp += stage3(v3, 0x29, 1);
        if (tmp == flag[i]){
            printf("%c",j);
            break;
            }
        }
    }
}
```

Flag: ***amateursCTF{r/programminghorror/comments/18x7vk9/}***


## revtale-1
{{< admonition >}}
28 solves / 406 points

Once upon a time...there was a binary with a flag.
{{< /admonition >}}
At first, I tried to reverse MiniTale.exe with IDA but that's a dumb way, I got nothing. After that, I noticed the data.win file, it seems not normal so I decided to research about that. After scrolling on the Internet for hours, I finally found that it is a database file of GameMaker, it contains script, audio, and many things. So the first thing is finding some tools that support us opening this kind of file and I found this works [UndertaleModTool](https://github.com/UnderminersTeam/UndertaleModTool). This is the ``src_check_flag`` function

```gml
funcs = [color_get_hue, color_get_green]
function scr_check_flag(argument0) //gml_Script_scr_check_flag
{
    l = string_lower(argument0)
    if ((string_pos("gaster", l) != 0))
    {
        window_set_caption("redacted")
        game_end(1)
    }
    if ((string_pos("frisk", l) != 0))
    {
        window_set_caption("don't make this hard")
        game_end(1)
    }
    if string_starts_with(argument0, "amateursCTF{")
    {
        if ((string_length(argument0) > 15))
        {
            a = scr_a(argument0)
            if ((a[12] == "{"))
            {
                window_set_caption("no")
                return 0;
            }
            for (i = 0; i < array_length(a); i++)
            {
            }
            aa = (ord(a[12]) & 4095)
            ab = (ord(a[13]) & 2047)
            ac = (ord(a[14]) & 1023)
            ad = (ord(a[15]) & 511)
            arr_op = array_reverse
            color_check = color_get_saturation
            if ((a[12] == a[13]) && (a[12] != a[14]))
            {
                if ((ac == (aa - 2)))
                {
                    if (((ab + 152) == self.color_check(16711935)) && ((ad + 133) == self.color_check(128)))
                    {
                        if (((obj_input_field.pk[0] ^ ord(a[16])) == 0))
                        {
                            if (((obj_input_field.pk[1] ^ ord(a[17])) == 0))
                            {
                                if (((obj_input_field.pk[2] ^ ord(a[18])) == 0))
                                {
                                    if ((ord(a[19]) == (power(2, 6) | 31)))
                                    {
                                        r = self.arr_op(["%", "3", "v", "0", "l", "_"], 0, 6)
                                        c = 0
                                        if ((a[19] == r[0]))
                                            c += 1
                                        if ((a[20] == r[1]))
                                            c += 2
                                        if ((a[21] == r[2]))
                                            c += 3
                                        if ((a[22] == r[3]))
                                            c += 4
                                        if ((a[23] == r[4]))
                                            c += 5
                                        if ((a[20] == a[21]))
                                            c += 5
                                        if ((c == 15))
                                        {
                                            if ((string_pos(file_text_read_string(file_text_open_read("f.txt")), argument0) != 0))
                                                return ((45887 == scr_c((((string_char_at(argument0, 29) + string_char_at(argument0, 30)) + string_char_at(argument0, 31)) + string_char_at(argument0, 32)))) && (ord(a[32]) == 125));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return 0;
        }
        else
            return 0;
    }
    else
        show_message(("flag wrapper missing... you entered " + argument0))
    return 0;
}

```

Now it is clear, that the flow is easy to reverse, i will put that flag only without any explanations.

Flag: ***amateursCTF{ggez_w3_l0v3_vm_b33f}***


## dill-with-it
{{< admonition >}}
27 solves / 408 points

Crisp green Larry lies Bathes, brining in vinegar Dill pickle delight
{{< /admonition >}}
```python
# Python 3.10.12
from pickle import loads
larry = b"\x80\x04ctypes\nFunctionType\n(ctypes\nCodeType\n(I1\nI0\nI0\nI4\nI8\nI67\nCbt\x00\xa0\x01|\x00d\x01\xa1\x02}\x01t\x02|\x01\x83\x01d\x00d\x00d\x02\x85\x03\x19\x00d\x00d\x03\x85\x02\x19\x00}\x00d\x04}\x02t\x03d\x05t\x04|\x00\x83\x01d\x06\x83\x03D\x00]\x11}\x03|\x02t\x05t\x00|\x00|\x03|\x03d\x06\x17\x00\x85\x02\x19\x00d\x07\x83\x02\x83\x017\x00}\x02q\x1d|\x02S\x00(NVbig\nI-1\nI-3\nV\nI0\nI8\nI2\nt(Vint\nVfrom_bytes\nVbin\nVrange\nVlen\nVchr\nt(\x8c\x04\xf0\x9f\x94\xa5\x8c\x04\xf0\x9f\xa4\xab\x8c\x04\xf0\x9f\xa7\x8f\x8c\x04\xf0\x9f\x8e\xb5tVdill-with-it\n\x8c\x04\xf0\x9f\x93\xaeI0\nC\x0c\x00\x01\x0c\x01\x1a\x01\x04\x01\x14\x01 \x01))t\x81cbuiltins\nglobals\n)R\x8c\x04\xf0\x9f\x93\xaet\x81\x940g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x05\x01.\xce\x966\x85R\x93g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x0b\x01\xa6&\xf6\xc6v\xa6tN.\xce\x85R\x93g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x06\x01.v\x96N\x0e\x85R\x93VWhat's the flag? \n\x85R0g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x06\x01.\xae\x0ev\x96\x85R\x93V> \n\x85R\x85R\x85R\x940g0\nC\x07\x01\xb6\xf6&v\x86N\x85Rg0\nC\x05\x01&\xa6\xa6\xce\x85R\x93Vfive nights as freddy\n\x85R0g0\nC\x07\x01\xb6\xf6&v\x86N\x85Rg0\nC\x08\x01\xa66ff\xae\x16\xce\x85R\x93g1\n\x85R0g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x05\x01.\xce\x966\x85R\x93g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x04\x01\x0e\x86\xb6\x85R\x93g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x0c\x01\xfa\xfaN\xf6\x1e\xfa\xfat.v\x96\x85R\x93g0\nC\x07\x01\xb6\xf6&v\x86N\x85Rg0\nC\n\x01\xce\xa6.\x9eF&v\x86N\x85R\x93g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x04\x01v\xa66\x85R\x93g1\n\x85R\x85Rg1\n\x87R\x85R\x940g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x04\x01\x9ev\x86\x85R\x93g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x04\x01\x0e\x86\xb6\x85R\x93g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x0c\x01\xfa\xfaN\xf6\x1e\xfa\xfat.v\x96\x85R\x93(I138\nI13\nI157\nI66\nI68\nI12\nI223\nI147\nI198\nI223\nI92\nI172\nI59\nI56\nI27\nI117\nI173\nI21\nI190\nI210\nI44\nI194\nI23\nI169\nI57\nI136\nI5\nI120\nI106\nI255\nI192\nI98\nI64\nI124\nI59\nI18\nI124\nI97\nI62\nI168\nI181\nI61\nI164\nI22\nI187\nI251\nI110\nI214\nI250\nI218\nI213\nI71\nI206\nI159\nI212\nI169\nI208\nI21\nI236\nlg2\n\x87R\x85R\x940g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x0b\x01\xfa\xfaN\xf6\xfa\xfat.v\x96\x85R\x93g3\ng0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x0b\x01\xfa\xfa\xa6v\xfa\xfat.v\x96\x85R\x93g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x04\x01v\xa66\x85R\x93g2\n\x85RI59\n\x86R\x86R\x940g0\nC\t\x01\xcev\x96.6\x96\xaeF\x85Rg0\nC\x11\x01\xfa\xfa\xb6\xa6.\x96.\xa6\xe6\xfa\xfat.\xce\x966\x85R\x93(VLooks like you got it!\nVNah, try again.\nlg4\n\x86R."
print(loads(larry))
```

This is pickle - flag checker challenge. So at first, I tried to decode it into human-readable python but it was not that easy. After research, I figured out that pickle files could be disassembled by [pickletools](https://docs.python.org/3/library/pickletools.html)

```python
0: \x80 PROTO      4
    2: c    GLOBAL     'types FunctionType'
   22: (    MARK
   23: c        GLOBAL     'types CodeType'
   39: (        MARK
   40: I            INT        1
   43: I            INT        0
   46: I            INT        0
   49: I            INT        4
   52: I            INT        8
   55: I            INT        67
   59: C            SHORT_BINBYTES b't\x00\xa0\x01|\x00d\x01\xa1\x02}\x01t\x02|\x01\x83\x01d\x00d\x00d\x02\x85\x03\x19\x00d\x00d\x03\x85\x02\x19\x00}\x00d\x04}\x02t\x03d\x05t\x04|\x00\x83\x01d\x06\x83\x03D\x00]\x11}\x03|\x02t\x05t\x00|\x00|\x03|\x03d\x06\x17\x00\x85\x02\x19\x00d\x07\x83\x02\x83\x017\x00}\x02q\x1d|\x02S\x00'
  159: (            MARK
  160: N                NONE
  161: V                UNICODE    'big'
  166: I                INT        -1
  170: I                INT        -3
  174: V                UNICODE    ''
  176: I                INT        0
  179: I                INT        8
  182: I                INT        2
  185: t                TUPLE      (MARK at 159)
  186: (            MARK
  187: V                UNICODE    'int'
  192: V                UNICODE    'from_bytes'
  204: V                UNICODE    'bin'
  209: V                UNICODE    'range'
  216: V                UNICODE    'len'
  221: V                UNICODE    'chr'
  226: t                TUPLE      (MARK at 186)
  227: (            MARK
  228: \x8c             SHORT_BINUNICODE '🔥'
  234: \x8c             SHORT_BINUNICODE '🤫'
  240: \x8c             SHORT_BINUNICODE '🧏'
  246: \x8c             SHORT_BINUNICODE '🎵'
  252: t                TUPLE      (MARK at 227)
  253: V            UNICODE    'dill-with-it'
  267: \x8c         SHORT_BINUNICODE '📮'
  273: I            INT        0
  276: C            SHORT_BINBYTES b'\x00\x01\x0c\x01\x1a\x01\x04\x01\x14\x01 \x01'
  290: )            EMPTY_TUPLE
  291: )            EMPTY_TUPLE
  292: t            TUPLE      (MARK at 39)
  293: \x81     NEWOBJ
  294: c        GLOBAL     'builtins globals'
  312: )        EMPTY_TUPLE
  313: R        REDUCE
  314: \x8c     SHORT_BINUNICODE '📮'
  320: t        TUPLE      (MARK at 22)
  321: \x81 NEWOBJ
  322: \x94 MEMOIZE    (as 0)
  323: 0    POP
  324: g    GET        0
  327: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  338: \x85 TUPLE1
  339: R    REDUCE
  340: g    GET        0
  343: C    SHORT_BINBYTES b'\x01.\xce\x966'
  350: \x85 TUPLE1
  351: R    REDUCE
  352: \x93 STACK_GLOBAL
  353: g    GET        0
  356: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  367: \x85 TUPLE1
  368: R    REDUCE
  369: g    GET        0
  372: C    SHORT_BINBYTES b'\x01\xa6&\xf6\xc6v\xa6tN.\xce'
  385: \x85 TUPLE1
  386: R    REDUCE
  387: \x93 STACK_GLOBAL
  388: g    GET        0
  391: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  402: \x85 TUPLE1
  403: R    REDUCE
  404: g    GET        0
  407: C    SHORT_BINBYTES b'\x01.v\x96N\x0e'
  415: \x85 TUPLE1
  416: R    REDUCE
  417: \x93 STACK_GLOBAL
  418: V    UNICODE    "What's the flag? "
  437: \x85 TUPLE1
  438: R    REDUCE
  439: 0    POP
  440: g    GET        0
  443: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  454: \x85 TUPLE1
  455: R    REDUCE
  456: g    GET        0
  459: C    SHORT_BINBYTES b'\x01.\xae\x0ev\x96'
  467: \x85 TUPLE1
  468: R    REDUCE
  469: \x93 STACK_GLOBAL
  470: V    UNICODE    '> '
  474: \x85 TUPLE1
  475: R    REDUCE
  476: \x85 TUPLE1
  477: R    REDUCE
  478: \x85 TUPLE1
  479: R    REDUCE
  480: \x94 MEMOIZE    (as 1)
  481: 0    POP
  482: g    GET        0
  485: C    SHORT_BINBYTES b'\x01\xb6\xf6&v\x86N'
  494: \x85 TUPLE1
  495: R    REDUCE
  496: g    GET        0
  499: C    SHORT_BINBYTES b'\x01&\xa6\xa6\xce'
  506: \x85 TUPLE1
  507: R    REDUCE
  508: \x93 STACK_GLOBAL
  509: V    UNICODE    'five nights as freddy'
  532: \x85 TUPLE1
  533: R    REDUCE
  534: 0    POP
  535: g    GET        0
  538: C    SHORT_BINBYTES b'\x01\xb6\xf6&v\x86N'
  547: \x85 TUPLE1
  548: R    REDUCE
  549: g    GET        0
  552: C    SHORT_BINBYTES b'\x01\xa66ff\xae\x16\xce'
  562: \x85 TUPLE1
  563: R    REDUCE
  564: \x93 STACK_GLOBAL
  565: g    GET        1
  568: \x85 TUPLE1
  569: R    REDUCE
  570: 0    POP
  571: g    GET        0
  574: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  585: \x85 TUPLE1
  586: R    REDUCE
  587: g    GET        0
  590: C    SHORT_BINBYTES b'\x01.\xce\x966'
  597: \x85 TUPLE1
  598: R    REDUCE
  599: \x93 STACK_GLOBAL
  600: g    GET        0
  603: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  614: \x85 TUPLE1
  615: R    REDUCE
  616: g    GET        0
  619: C    SHORT_BINBYTES b'\x01\x0e\x86\xb6'
  625: \x85 TUPLE1
  626: R    REDUCE
  627: \x93 STACK_GLOBAL
  628: g    GET        0
  631: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  642: \x85 TUPLE1
  643: R    REDUCE
  644: g    GET        0
  647: C    SHORT_BINBYTES b'\x01\xfa\xfaN\xf6\x1e\xfa\xfat.v\x96'
  661: \x85 TUPLE1
  662: R    REDUCE
  663: \x93 STACK_GLOBAL
  664: g    GET        0
  667: C    SHORT_BINBYTES b'\x01\xb6\xf6&v\x86N'
  676: \x85 TUPLE1
  677: R    REDUCE
  678: g    GET        0
  681: C    SHORT_BINBYTES b'\x01\xce\xa6.\x9eF&v\x86N'
  693: \x85 TUPLE1
  694: R    REDUCE
  695: \x93 STACK_GLOBAL
  696: g    GET        0
  699: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  710: \x85 TUPLE1
  711: R    REDUCE
  712: g    GET        0
  715: C    SHORT_BINBYTES b'\x01v\xa66'
  721: \x85 TUPLE1
  722: R    REDUCE
  723: \x93 STACK_GLOBAL
  724: g    GET        1
  727: \x85 TUPLE1
  728: R    REDUCE
  729: \x85 TUPLE1
  730: R    REDUCE
  731: g    GET        1
  734: \x87 TUPLE3
  735: R    REDUCE
  736: \x85 TUPLE1
  737: R    REDUCE
  738: \x94 MEMOIZE    (as 2)
  739: 0    POP
  740: g    GET        0
  743: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  754: \x85 TUPLE1
  755: R    REDUCE
  756: g    GET        0
  759: C    SHORT_BINBYTES b'\x01\x9ev\x86'
  765: \x85 TUPLE1
  766: R    REDUCE
  767: \x93 STACK_GLOBAL
  768: g    GET        0
  771: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  782: \x85 TUPLE1
  783: R    REDUCE
  784: g    GET        0
  787: C    SHORT_BINBYTES b'\x01\x0e\x86\xb6'
  793: \x85 TUPLE1
  794: R    REDUCE
  795: \x93 STACK_GLOBAL
  796: g    GET        0
  799: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
  810: \x85 TUPLE1
  811: R    REDUCE
  812: g    GET        0
  815: C    SHORT_BINBYTES b'\x01\xfa\xfaN\xf6\x1e\xfa\xfat.v\x96'
  829: \x85 TUPLE1
  830: R    REDUCE
  831: \x93 STACK_GLOBAL
  832: (    MARK
  833: I        INT        138
  838: I        INT        13
  842: I        INT        157
  847: I        INT        66
  851: I        INT        68
  855: I        INT        12
  859: I        INT        223
  864: I        INT        147
  869: I        INT        198
  874: I        INT        223
  879: I        INT        92
  883: I        INT        172
  888: I        INT        59
  892: I        INT        56
  896: I        INT        27
  900: I        INT        117
  905: I        INT        173
  910: I        INT        21
  914: I        INT        190
  919: I        INT        210
  924: I        INT        44
  928: I        INT        194
  933: I        INT        23
  937: I        INT        169
  942: I        INT        57
  946: I        INT        136
  951: I        INT        5
  954: I        INT        120
  959: I        INT        106
  964: I        INT        255
  969: I        INT        192
  974: I        INT        98
  978: I        INT        64
  982: I        INT        124
  987: I        INT        59
  991: I        INT        18
  995: I        INT        124
 1000: I        INT        97
 1004: I        INT        62
 1008: I        INT        168
 1013: I        INT        181
 1018: I        INT        61
 1022: I        INT        164
 1027: I        INT        22
 1031: I        INT        187
 1036: I        INT        251
 1041: I        INT        110
 1046: I        INT        214
 1051: I        INT        250
 1056: I        INT        218
 1061: I        INT        213
 1066: I        INT        71
 1070: I        INT        206
 1075: I        INT        159
 1080: I        INT        212
 1085: I        INT        169
 1090: I        INT        208
 1095: I        INT        21
 1099: I        INT        236
 1104: l        LIST       (MARK at 832)
 1105: g    GET        2
 1108: \x87 TUPLE3
 1109: R    REDUCE
 1110: \x85 TUPLE1
 1111: R    REDUCE
 1112: \x94 MEMOIZE    (as 3)
 1113: 0    POP
 1114: g    GET        0
 1117: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
 1128: \x85 TUPLE1
 1129: R    REDUCE
 1130: g    GET        0
 1133: C    SHORT_BINBYTES b'\x01\xfa\xfaN\xf6\xfa\xfat.v\x96'
 1146: \x85 TUPLE1
 1147: R    REDUCE
 1148: \x93 STACK_GLOBAL
 1149: g    GET        3
 1152: g    GET        0
 1155: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
 1166: \x85 TUPLE1
 1167: R    REDUCE
 1168: g    GET        0
 1171: C    SHORT_BINBYTES b'\x01\xfa\xfa\xa6v\xfa\xfat.v\x96'
 1184: \x85 TUPLE1
 1185: R    REDUCE
 1186: \x93 STACK_GLOBAL
 1187: g    GET        0
 1190: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
 1201: \x85 TUPLE1
 1202: R    REDUCE
 1203: g    GET        0
 1206: C    SHORT_BINBYTES b'\x01v\xa66'
 1212: \x85 TUPLE1
 1213: R    REDUCE
 1214: \x93 STACK_GLOBAL
 1215: g    GET        2
 1218: \x85 TUPLE1
 1219: R    REDUCE
 1220: I    INT        59
 1224: \x86 TUPLE2
 1225: R    REDUCE
 1226: \x86 TUPLE2
 1227: R    REDUCE
 1228: \x94 MEMOIZE    (as 4)
 1229: 0    POP
 1230: g    GET        0
 1233: C    SHORT_BINBYTES b'\x01\xcev\x96.6\x96\xaeF'
 1244: \x85 TUPLE1
 1245: R    REDUCE
 1246: g    GET        0
 1249: C    SHORT_BINBYTES b'\x01\xfa\xfa\xb6\xa6.\x96.\xa6\xe6\xfa\xfat.\xce\x966'
 1268: \x85 TUPLE1
 1269: R    REDUCE
 1270: \x93 STACK_GLOBAL
 1271: (    MARK
 1272: V        UNICODE    'Looks like you got it!'
 1296: V        UNICODE    'Nah, try again.'
 1313: l        LIST       (MARK at 1271)
 1314: g    GET        4
 1317: \x86 TUPLE2
 1318: R    REDUCE
 1319: .    STOP
highest protocol among opcodes = 4
```

As you can see, it is so difficult to understand, so that I researched more about some tools can debug pickle and luckily we got that [pickledbg](https://github.com/Legoclones/pickledbg). Now our jobs will be easier... or not?  🤣

First, it will receive out input and convert to int and save in memo 

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/e947e814-172b-4f8e-bb22-912bccf87077)

After that, it will call ``five nights as freddy`` function, and do some random shuffle and save it again in memo.

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/733cdd40-3a40-4a0b-bed3-c2ae7f152b8a)

Next, it will xor the shuffled array with these bytes 
> \xd5d\xf0x0?\x86\xfc\xb6\xab\x03\x96RY*)\xca`\xda\xb7\x01\xb9j\xc8\\\xe7bH\x0f\x8c\xb4=2#HsO\x0ea\xc9\xdbO\xc8d\xf7\x96\r\x90\xae\x99\xbe\x18\xbd\xcd\xa0\xdd\xe4J\x84

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/4b1fbb9e-f4ed-4554-99f9-e14b7126180b)

Finally, it will compare with array in stack.

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/1f45766f-6020-4b67-9bb2-0a04059b3e8d)

Now it is easy to reverse. My final script:

```python
from pwn import *
flag_shuf = [138, 13, 157, 66, 68, 12, 223, 147, 198, 223, 92, 172, 59, 56, 27, 117, 173, 21, 190, 210, 44, 194, 23, 169, 57, 136, 5, 120, 106, 255, 192, 98, 64, 124, 59, 18, 124, 97, 62, 168, 181, 61, 164, 22, 187, 251, 110, 214, 250, 218, 213, 71, 206, 159, 212, 169, 208, 21, 236]
xor_key = b'\xd5d\xf0x0?\x86\xfc\xb6\xab\x03\x96RY*)\xca`\xda\xb7\x01\xb9j\xc8\\\xe7bH\x0f\x8c\xb4=2#HsO\x0ea\xc9\xdbO\xc8d\xf7\x96\r\x90\xae\x99\xbe\x18\xbd\xcd\xa0\xdd\xe4J\x84'
unshuf_flag = xor(flag_shuf,xor_key)
orin_inndex = [48, 19, 44, 50, 33, 17, 39, 52, 12, 54, 29, 55, 41, 2, 13, 49, 30, 5, 57, 28, 18, 11, 58, 0, 56, 31, 51, 45, 4, 42, 3, 25, 37, 43, 20, 32, 47, 23, 34, 53, 22, 38, 35, 6, 16, 1, 14, 10, 9, 8, 15, 40, 7, 46, 24, 26, 36, 21, 27]
for i in range(len(orin_inndex)):
    c = orin_inndex.index(i)
    print(chr(unshuf_flag[c]),end="")
```

Flag: ***amateursCTF{p1ckL3-is_not_the_goat_l4rrY_is_m0R3_\:goat:ed}***

## gogogaga
{{< admonition >}}
17 solves / 436 points

"wow its my favorite language to rev" - nobody
{{< /admonition >}}

First time, I could solve golang reverse challenge. Btw, this challenge makes me so crazy. It took me nearly 12 hours to solve (~~because of my skill issue~~). Download the binary and try to run it, it simply takes the key and if it is correct, we will get the flag.

Open bin with IDA and start analyzing, golang is so shit when it is decompiled :+1:. At first, it will take our input into ``main_checkKey`` function. In that function has more 5 ``main_checkKey_func1`` to ``main_checkKey_func5`` 💀. The nightmare has come, but we need to do this.

```C
// main.checkKey
bool __golang main_checkKey(string key)
{
  __int64 v1; // r14
  __int64 v2; // rcx
  __int64 v4; // rdx
  __int64 v5; // rcx
  unsigned __int64 j; // rbx
  runtime_funcval *v7; // rax
  __int64 v8; // rcx
  runtime_hchan *v9; // rdx
  _QWORD *v10; // r11
  runtime_funcval *v11; // rax
  __int64 v12; // rcx
  runtime_hchan *v13; // rdx
  _QWORD *v14; // r11
  runtime_funcval *v15; // rax
  __int64 v16; // rcx
  runtime_hchan *v17; // rdx
  _QWORD *v18; // r11
  runtime_funcval *v19; // rax
  __int64 v20; // rcx
  runtime_hchan *v21; // rdx
  _QWORD *v22; // r11
  runtime_funcval *v23; // rax
  __int64 v24; // rcx
  runtime_hchan *v25; // rdx
  _QWORD *v26; // r11
  __int64 i; // rax
  uint8 v28; // si
  uint8 v29; // si
  bool elem; // [rsp+1h] [rbp-31h] BYREF
  __int64 v31; // [rsp+2h] [rbp-30h]
  uintptr v32; // [rsp+Ah] [rbp-28h]
  __int64 *array; // [rsp+12h] [rbp-20h]
  runtime_hchan *c; // [rsp+1Ah] [rbp-18h]
  __int64 v35; // [rsp+22h] [rbp-10h]
  void *retaddr; // [rsp+32h] [rbp+0h] BYREF
  string v37; // 0:rcx.8,8:rdi.8
  _slice_string v38; // 0:rax.8,8:rbx.8,16:rcx.8

  if ( (unsigned __int64)&retaddr <= *(_QWORD *)(v1 + 16) )
  {
    runtime_morestack_noctxt();
    JUMPOUT(0x495FC5LL);
  }
  v37.str = (uint8 *)&runtime_gcbits__ptr_;
  v37.len = 1LL;
  v38 = strings_genSplit(key, v37, 0LL, -1LL);
  if ( v38.len != 5 )
    return 0;
  v2 = 0LL;
LABEL_6:
  if ( v2 >= 5 )
  {
    array = (__int64 *)v38.array;
    c = runtime_makechan((internal_abi_ChanType *)&RTYPE_chan_bool_0, 5LL);
    v32 = array[1];
    v35 = *array;
    v7 = (runtime_funcval *)runtime_newobject((internal_abi_Type *)&stru_4A7560);
    v7->fn = (uintptr)main_checkKey_func1;
    v7[2].fn = v32;
    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
    {
      runtime_gcWriteBarrier2();
      v8 = v35;
      *v10 = v35;
      v9 = c;
      v10[1] = c;
    }
    else
    {
      v8 = v35;
      v9 = c;
    }
    v7[1].fn = v8;
    v7[3].fn = (uintptr)v9;
    runtime_newproc(v7);
    v32 = array[3];
    v35 = array[2];
    v11 = (runtime_funcval *)runtime_newobject((internal_abi_Type *)&stru_4A7600);
    v11->fn = (uintptr)main_checkKey_func2;
    v11[2].fn = v32;
    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
    {
      runtime_gcWriteBarrier2();
      v12 = v35;
      *v14 = v35;
      v13 = c;
      v14[1] = c;
    }
    else
    {
      v12 = v35;
      v13 = c;
    }
    v11[1].fn = v12;
    v11[3].fn = (uintptr)v13;
    runtime_newproc(v11);
    v32 = array[5];
    v35 = array[4];
    v15 = (runtime_funcval *)runtime_newobject((internal_abi_Type *)&stru_4A76A0);
    v15->fn = (uintptr)main_checkKey_func3;
    v15[2].fn = v32;
    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
    {
      runtime_gcWriteBarrier2();
      v16 = v35;
      *v18 = v35;
      v17 = c;
      v18[1] = c;
    }
    else
    {
      v16 = v35;
      v17 = c;
    }
    v15[1].fn = v16;
    v15[3].fn = (uintptr)v17;
    runtime_newproc(v15);
    v32 = array[7];
    v35 = array[6];
    v19 = (runtime_funcval *)runtime_newobject((internal_abi_Type *)&stru_4A7740);
    v19->fn = (uintptr)main_checkKey_func4;
    v19[2].fn = v32;
    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
    {
      runtime_gcWriteBarrier2();
      v20 = v35;
      *v22 = v35;
      v21 = c;
      v22[1] = c;
    }
    else
    {
      v20 = v35;
      v21 = c;
    }
    v19[1].fn = v20;
    v19[3].fn = (uintptr)v21;
    runtime_newproc(v19);
    v32 = array[9];
    v35 = array[8];
    v23 = (runtime_funcval *)runtime_newobject((internal_abi_Type *)&stru_4A77E0);
    v23->fn = (uintptr)main_checkKey_func5;
    v23[2].fn = v32;
    if ( *(_DWORD *)&runtime_writeBarrier.enabled )
    {
      runtime_gcWriteBarrier2();
      v24 = v35;
      *v26 = v35;
      v25 = c;
      v26[1] = c;
    }
    else
    {
      v24 = v35;
      v25 = c;
    }
    v23[1].fn = v24;
    v23[3].fn = (uintptr)v25;
    runtime_newproc(v23);
    for ( i = 0LL; i < 5; i = v31 + 1 )
    {
      v31 = i;
      elem = 0;
      runtime_chanrecv1(c, &elem);
      if ( !elem )
        return 0;
    }
    return 1;
  }
  else
  {
    v4 = v2;
    v5 = v2;
    if ( v38.array[v5].len == 5 )
    {
      for ( j = 0LL; ; ++j )
      {
        if ( (__int64)j >= 5 )
        {
          v2 = v4 + 1;
          goto LABEL_6;
        }
        if ( j >= v38.array[v5].len )
          runtime_panicIndex();
        v28 = v38.array[v5].str[j];
        elem = v28 < 0x41u;
        if ( v28 >= 0x41u )
        {
          if ( j >= v38.array[v5].len )
            runtime_panicIndex();
          elem = v38.array[v5].str[j] > 0x5Au;
        }
        if ( elem )
        {
          if ( j >= v38.array[v5].len )
            runtime_panicIndex();
          v29 = v38.array[v5].str[j];
          elem = v29 < 0x30u;
          if ( v29 >= 0x30u )
          {
            if ( j >= v38.array[v5].len )
              runtime_panicIndex();
            elem = v38.array[v5].str[j] > 0x39u;
          }
          if ( elem )
            break;
        }
      }
      return 0;
    }
    else
    {
      return 0;
    }
  }
}
```

Before talking about 5 check functions, the most important thing we need to consider is ``strings_genSplit``. During the contest, I didn't notice this so it took a long time to solve. About that function, it simply counts how many **-** in our string and separates it into 5 parts corresponding to 5 check functions. So we need 4 **-** in our string, and after that, it will go down and check each input character if they are in the range ``0->9`` and ``A-Z``. If two conditions are correct, it will go to the main function check.

```C
v38 = strings_genSplit(key, v37, 0LL, -1LL);
if ( v38.len != 5 )
return 0;
v2 = 0LL;
LABEL_6:

...

else
  {
    v4 = v2;
    v5 = v2;
    if ( v38.array[v5].len == 5 )
    {
      for ( j = 0LL; ; ++j )
      {
        if ( (__int64)j >= 5 )
        {
          v2 = v4 + 1;
          goto LABEL_6;
        }
        if ( j >= v38.array[v5].len )
          runtime_panicIndex();
        v28 = v38.array[v5].str[j];
        elem = v28 < 0x41u;
        if ( v28 >= 0x41u )
        {
          if ( j >= v38.array[v5].len )
            runtime_panicIndex();
          elem = v38.array[v5].str[j] > 0x5Au;
        }
        if ( elem )
        {
          if ( j >= v38.array[v5].len )
            runtime_panicIndex();
          v29 = v38.array[v5].str[j];
          elem = v29 < 0x30u;
          if ( v29 >= 0x30u )
          {
            if ( j >= v38.array[v5].len )
              runtime_panicIndex();
            elem = v38.array[v5].str[j] > 0x39u;
          }
          if ( elem )
            break;
        }
      }
      return 0;
    }
    else
    {
      return 0;
    }
  }
```
``main_checkKey_func1`` is just compare the string with base64 encoding, we can easily get the first string is **LARRY**


```C
c = (runtime_hchan *)check;
  len = key.len;
  v10.str = key.str;
  v10.len = len;
  v11 = runtime_stringtoslicebyte((runtime_tmpBuf *)&elem[1], v10);
  cap = v11.cap;
  v11.cap = v11.len;
  v11.len = (int)v11.array;
  v5 = encoding_base64__ptr_Encoding_EncodeToString(encoding_base64_StdEncoding, *(_slice_uint8 *)&v11.len);
  v6 = v5.len == 8 && *(_QWORD *)v5.str == 0x3D6B6C5553464554LL;
  elem[0] = v6;
  runtime_chansend1(c, elem);
```

``main_checkKey_func2`` will check if our input is in range ``0->9`` and does basic compare.

```C
while ( v3 < 5 )
{
if ( key.len <= (unsigned __int64)v3 )
  runtime_panicIndex();
v6 = key.str[v3];
elem[0] = v6 < '0';
if ( v6 >= '0' )
  elem[0] = key.str[v3] > '9';
if ( elem[0] )
{
  runtime_chansend1((runtime_hchan *)check, &runtime_egcbss);
  return;
}
v5 = (unsigned __int8)(key.str[v3++] - 48);
v4 += v5;
}
elem[0] = v4 == 35;
runtime_chansend1((runtime_hchan *)check, elem);
```

Part 2:

```C
#include <stdio.h>
int main(){
    for (int i = 48; i < 58; i++){
        for (int j = 48; j < 58; j++){
            for (int x = 48; x < 58; x++){
                for (int y = 48; y < 58; y++){
                    for (int z = 48; z < 58; z++){
                    int tmp = (i - 48) + (j - 48) + (x - 48) + (y - 48) + (z - 48);
                    if (tmp == 35){
                        printf("%c%c%c%c%c :%d\n",i,j,x,y,z,tmp);
                }
              }
            }
        }
      }
    }
}
```
I will take **77777** for part 2. Next will be ``main_checkKey_func3``, this function is similar with part 2 but the most different is we need to find a string that each character is different from each one. This is because of ``runtime_mapassign()``

```C
while ( v6 < 5 )
  {
    if ( len <= v6 )
      runtime_panicIndex();
    v7 = v5[v6];
    if ( (unsigned __int8)v7 < 0x41u
      || (unsigned __int8)v7 > 0x5Au
      || (v10 = v6, v9 = v7, *(_BYTE *)runtime_mapaccess1((internal_abi_MapType *)&RTYPE_map_uint8_bool_0, &h, &v9)) )
    {
      runtime_chansend1(c, &runtime_egcbss);
      return;
    }
    v9 = keya[v10];
    *(_BYTE *)runtime_mapassign((internal_abi_MapType *)&RTYPE_map_uint8_bool_0, &h, &v9) = 1;
    v6 = v10 + 1;
    len = key.len;
    v5 = keya;
  }
  v18.str = v5;
  v18.len = len;
  v19 = runtime_stringtoslicebyte((runtime_tmpBuf *)buf, v18);
  for ( i = 0LL; i < 5; ++i )
  {
    if ( v19.len <= (unsigned __int64)i )
      runtime_panicIndex();
    v19.array[i] ^= 0x60;
  }
  v17 = runtime_slicebytetostring((runtime_tmpBuf *)v12, v19.array, v19.len);
  main_Tuesday(v17, (chan_bool)c);
```

Part 3:

```C
#include <stdio.h>

int check_diff(int i, int j, int x, int y, int z) {
    int values[5] = {i, j, x, y, z};
    for (int idx1 = 0; idx1 < 5; idx1++) {
        for (int idx2 = idx1 + 1; idx2 < 5; idx2++) {
            if (values[idx1] == values[idx2]) {
                return 0;
            }
        }
    }
    return 1;
}
int main(){
    for (int i = 80; i < 90; i++){
        for (int j = 80; j < 90; j++){
            for (int x = 80; x < 90; x++){
                for (int y = 80; y < 90; y++){
                    for (int z = 80; z < 90; z++){
                    int tmp = ((i ^ 0x60) - 48) + ((j ^ 0x60) - 48) + ((x ^ 0x60) - 48) + ((y ^ 0x60) - 48) + ((z ^ 0x60) - 48);
                    if (tmp == 35 && check_diff(i,j,x,y,z)){
                        printf("%c%c%c%c%c :%d\n",i,j,x,y,z,tmp);
                    }
              }
            }
        }
      }
    }
}
```
I will choose **WVYUX**. ``main_checkKey_func4`` is the tricky one, if you just read the pseudocode, you will not be able to solve this. This is the 
pseudocode:

```C
v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  while ( v4 < 5 )
  {
    if ( v15.len <= (unsigned __int64)v4 )
      runtime_panicIndex();
    for ( i = v15.array[v4]; (_BYTE)i; i = v10 )
    {
      v8 = v5-- + 1;
      v9 = v6-- + 1;
      v10 = i;
      if ( (i & 1) != 0 )
        v5 = v8;
      if ( (i & 2) != 0 )
        v6 = v9;
      LOBYTE(v10) = (unsigned __int8)i >> 2;
    }
    ++v4;
  }
  elem[0] = v5 == 5;
  if ( v5 == 5 )
    elem[0] = v6 == 3;
  runtime_chansend1(c, elem);
}
```
Look easy right? You are wrong 🤣. If you just copy and paste that code, im sure you will not get any correct solution. 

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/986e87d9-3d83-4a92-8ec0-a690ffbe0b3d)

This the correct what this function does. We can implement this easily and got suitable value.

```python
def sus(i1, i2, i3, i4, i5):

    rdx = 0
    rsi = 0

    input = i1
    while input:
        r8 = rdx + 1
        rdx -= 1
        r9 = rsi + 1
        rsi -= 1

        if input & 1 != 0:
            rdx = r8
        if input & 2 != 0:
            rsi = r9
        input >>=2

    input = i2
    while input:
        r8 = rdx + 1
        rdx -= 1
        r9 = rsi + 1
        rsi -= 1

        if input & 1 != 0:
            rdx = r8
        if input & 2 != 0:
            rsi = r9
        input >>=2

    input = i3
    while input:
        r8 = rdx + 1
        rdx -= 1
        r9 = rsi + 1
        rsi -= 1

        if input & 1 != 0:
            rdx = r8
        if input & 2 != 0:
            rsi = r9
        input >>=2
       

    input = i4
    while input:
        r8 = rdx + 1
        rdx -= 1
        r9 = rsi + 1
        rsi -= 1

        if input & 1 != 0:
            rdx = r8
        if input & 2 != 0:
            rsi = r9
        input >>=2
    
    input = i5
    while input:
        r8 = rdx + 1
        rdx -= 1
        r9 = rsi + 1
        rsi -= 1

        if input & 1 != 0:
            rdx = r8
        if input & 2 != 0:
            rsi = r9
        input >>=2

    
    if rdx == 5 and rsi == 3:
        print(chr(i1) + chr(i2) + chr(i3) + chr(i4) +chr(i5))


for i in range(48, 58):
    for j in range(48, 58):
        for x in range(48, 58):
            for y in range(48, 58):
                for z in range(48, 58):
                    sus(i,j,x,y,z)
```

So fourth part will be **99994**. Combine 4 parts, now we have **LARRY-77777-WVYUX-99994-**. The hardest part is comming up next, the ``main_checkKey_func5``

```C
key_8 = key.len;
keya = (char *)key.str;
v23 = check;
qmemcpy(v21, "UNL0CK", sizeof(v21));
v3 = (char *)((__int64 (__fastcall *)(_BYTE *))loc_45E299)(v19);
v5 = 0LL;
while ( v5 < 6 )
{
v22 = v5;
v6 = runtime_makeslice((internal_abi_Type *)&RTYPE_uint_0, 7LL, 7LL);
v7 = v22;
v8 = 3 * v22;
v25[v8] = 7LL;
v25[v8 + 1] = 7LL;
v25[v8 - 1] = (__int64)v6;
v5 = v7 + 1;
v3 = keya;
v4 = (runtime_hchan *)v23;
key.len = key_8;
}
for ( i = 0LL; i < 6; ++i )
{
if ( !v25[3 * i] )
  runtime_panicIndex();
*(_QWORD *)v25[3 * i - 1] = i;
}
for ( j = 0LL; j < 7; ++j )
{
if ( (unsigned __int64)j >= v25[0] )
  runtime_panicIndex();
*(_QWORD *)(v24 + 8 * j) = j;
}
for ( k = 1LL; k < 6; ++k )
{
for ( m = 1LL; (__int64)m < 7; ++m )
{
  if ( key.len <= (unsigned __int64)(k - 1) )
    runtime_panicIndex();
  v13 = m - 1;
  if ( v21[m - 1] == v3[k - 1] ) // Check each input with each string v21
  {
    if ( *(&v22 + 3 * k) <= v13 )
      runtime_panicIndex();
    if ( m >= v25[3 * k] )
      runtime_panicIndex();
    *(_QWORD *)(v25[3 * k - 1] + 8 * m) = *(_QWORD *)(*(_QWORD *)&v19[24 * k + 24] + 8 * m - 8); // doing A stuff
  }
  else
  {
    v14 = *(char **)&v19[24 * k + 24]; // doing B stuffs
    if ( m >= *(&v22 + 3 * k) )
      runtime_panicIndex();
    v15 = v25[3 * k];
    v16 = *(_QWORD *)&v14[8 * m];
    v17 = (char *)v25[3 * k - 1];
    if ( v15 <= v13 )
      runtime_panicIndex();
    v18 = *(_QWORD *)&v14[8 * m - 8];
    if ( *(_QWORD *)&v17[8 * m - 8] < v16 )
      v16 = *(_QWORD *)&v17[8 * m - 8];
    if ( v18 < v16 )
      v16 = v18;
    if ( m >= v15 )
      runtime_panicIndex();
    *(_QWORD *)&v17[8 * m] = v16 + 1; 
  }
}
}
```

After debugging and reading the code, I didn't completely understand what this function does :crying_cat_face:. But to summarizing, each input's character will be compared with v21 string, if it is the same, it will do A stuff, if not will do B stuff. So my solution will be brute-force... with the input must be a combination of ``UNL0CK`` with some characters. After brute-forcing, if you use a combination from this string ``UNL0CK1``, you will have the final answer. First, i use ``crunch`` to automatically generate combinations for me by ``crunch 5 5 UNL0CK1 > tmp.txt``. And using this script to brute force.


```python
from pwn import *

flag = "LARRY-77777-WVYUX-99994-"
def send_combinations(file_name):
    with open(file_name, 'r') as file:
        for line in file:
            combination = line.strip()  # 
            payload = flag + combination
            p = process("./main") 
            p.recvuntil('> ')
            p.sendline(payload)
            l = p.recvall()
            if b"again" not in l:
                print(l)
                print(combination)
                p.interactive()
            else:
                p.close()
            
send_combinations("tmp.txt")
```

Nice the final part is **UUUCK**. So the key will be **LARRY-99935-WVYUX-99994-UUUCK**

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/4afd0aae-ff7c-4eea-96c7-1ec02afb0739)

Flag: ***amateursCTF{c4nt_b3liev3_g0_ogl3_r30p3ned_CTF_sp0n50rs}***
