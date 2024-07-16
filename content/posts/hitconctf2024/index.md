---
weight: 1
title: "HITCON CTF 2024"
date: 2024-07-16
lastmod: 2024-07-16
draft: false
author: "clowncs"
authorLink: "https://clowncs.github.io"
description: "Solutions for some reverse challenges in KCSC CTF 2024"
tags: ["RE", "Honor", "2024"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---
Solutions for some reverse challenges in HITCON CTF 2024

<!--more-->

# REV
## Revisual
#### p/s: This challenge me (@clowncs) collabed with @dad0qbu who helps me a lot
Download the source code, we figure out this is JS obfuscate. At first i tried to use some online tools to deob it but it couldn't run. But it can make it more understandable.

```javascript
function seem_main(point) {
  let _0x526465 = some_method.wtf(point[19], point[3], point[5]) * 25,
    _0x27d483 = some_method.wtf(point[7], point[20], point[18]) * 25,
    _0x47edd7 = some_method.wtf(point[11], point[22], point[18]) * 25,
    _0x3c8060 = some_method.wtf(point[5], point[17], point[2]) * 25,
    _0x315313 = some_method.wtf(point[20], point[13], point[5]) * 25,
    _0x3cef24 = some_method.wtf(point[11], point[1], point[21]) * 25,
    _0x2ee445 = some_method.wtf(point[8], point[11], point[1]) * 25,
    _0x5e280a = some_method.wtf(point[9], point[5], point[4]) * 25,
    _0x5f6c26 = some_method.wtf(point[17], point[9], point[21]) * 25,
    _0x13e7aa = some_method.wtf(point[23], point[9], point[20]) * 25,
    _0x9d682e = some_method.wtf(point[16], point[5], point[4]) * 25,
    _0x277f3c = some_method.wtf(point[16], point[14], point[13]) * 25,
    _0x2f58be = some_method.wtf(point[5], point[6], point[10]) * 25,
    _0x5a6698 = some_method.wtf(point[2], point[11], point[5]) * 25,
    _0x52d3ed = some_method.wtf(point[11], point[3], point[1]) * 25,
    _0x4320e6 = some_method.wtf(point[12], point[3], point[10]) * 25,
    _0xf9ef4b = some_method.wtf(point[14], point[1], point[9]) * 25,
    _0x429aaf = some_method.wtf(point[18], point[11], point[17]) * 25,
    _0x1a4487 = some_method.wtf(point[12], point[15], point[2]) * 25,
    _0x4c135d = some_method.wtf(point[22], point[0], point[19]) * 25,
    _0x5c13fb = 0

  _0x5c13fb += this_is_abs(
    0.3837876686390533 - some_method.gtfo(_0x3cef24, _0xf9ef4b, _0x5f6c26, 16, 21)
  )
  _0x5c13fb += this_is_abs(
    0.21054889940828397 - some_method.gtfo(_0x52d3ed, _0x3cef24, _0x2ee445, 8, 2)
  )
  _0x5c13fb += this_is_abs(
    0.475323349112426 - some_method.gtfo(_0x3cef24, _0x429aaf, _0x2f58be, 0, 20)
  )
  _0x5c13fb += this_is_abs(
    0.6338370887573964 - some_method.gtfo(_0x3c8060, _0x27d483, _0x2f58be, 8, 4)
  )
  _0x5c13fb += this_is_abs(
    0.4111607928994082 - some_method.gtfo(_0x47edd7, _0x52d3ed, _0x4320e6, 23, 1)
  )
  _0x5c13fb += this_is_abs(
    0.7707577751479291 - some_method.gtfo(_0x429aaf, _0x3c8060, _0x277f3c, 20, 6)
  )
  _0x5c13fb += this_is_abs(
    0.7743081420118344 - some_method.gtfo(_0x13e7aa, _0x5a6698, _0x3c8060, 9, 10)
  )
  _0x5c13fb += this_is_abs(
    0.36471487573964495 - some_method.gtfo(_0x5f6c26, _0x526465, _0x315313, 18, 8)
  )
  _0x5c13fb += this_is_abs(
    0.312678449704142 - some_method.gtfo(_0x4320e6, _0x13e7aa, _0x429aaf, 0, 17)
  )
  _0x5c13fb += this_is_abs(
    0.9502808165680473 - some_method.gtfo(_0x1a4487, _0x13e7aa, _0x3c8060, 22, 10)
  )
  _0x5c13fb += this_is_abs(
    0.5869052899408282 - some_method.gtfo(_0x2f58be, _0x5e280a, _0x47edd7, 14, 10)
  )
  _0x5c13fb += this_is_abs(
    0.9323389467455623 - some_method.gtfo(_0x429aaf, _0x47edd7, _0x2f58be, 12, 7)
  )
  _0x5c13fb += this_is_abs(
    0.4587118106508875 - some_method.gtfo(_0x2ee445, _0x5a6698, _0x47edd7, 4, 21)
  )
  _0x5c13fb += this_is_abs(
    0.14484472189349107 - some_method.gtfo(_0x4320e6, _0x13e7aa, _0x52d3ed, 7, 15)
  )
  _0x5c13fb += this_is_abs(
    0.7255550059171598 - some_method.gtfo(_0x3cef24, _0x429aaf, _0x1a4487, 9, 23)
  )
  _0x5c13fb += this_is_abs(
    0.5031261301775147 - some_method.gtfo(_0x3c8060, _0x47edd7, _0x52d3ed, 7, 1)
  )
  _0x5c13fb += this_is_abs(
    0.1417352189349112 - some_method.gtfo(_0x2ee445, _0x52d3ed, _0x5f6c26, 16, 14)
  )
  _0x5c13fb += this_is_abs(
    0.5579334437869822 - some_method.gtfo(_0x52d3ed, _0x47edd7, _0x1a4487, 19, 11)
  )
  _0x5c13fb += this_is_abs(
    0.48502262721893485 -
      some_method.gtfo(_0x9d682e, _0x315313, _0x5e280a, 23, 18)
  )
  _0x5c13fb += this_is_abs(
    0.5920916568047336 - some_method.gtfo(_0x5e280a, _0x5f6c26, _0x27d483, 19, 6)
  )
  _0x5c13fb += this_is_abs(
    0.7222713017751479 - some_method.gtfo(_0xf9ef4b, _0x47edd7, _0x315313, 8, 16)
  )
  _0x5c13fb += this_is_abs(
    0.12367382248520711 - some_method.gtfo(_0x9d682e, _0x4320e6, _0x2f58be, 9, 5)
  )
  _0x5c13fb += this_is_abs(
    0.4558028402366864 - some_method.gtfo(_0x277f3c, _0x9d682e, _0x47edd7, 10, 2)
  )
  _0x5c13fb += this_is_abs(
    0.8537692426035504 - some_method.gtfo(_0x429aaf, _0x13e7aa, _0x5a6698, 4, 11)
  )
  _0x5c13fb += this_is_abs(
    0.9618170650887574 - some_method.gtfo(_0x2f58be, _0x1a4487, _0x429aaf, 15, 2)
  )
  _0x5c13fb += this_is_abs(
    0.22088933727810647 - some_method.gtfo(_0x526465, _0x5e280a, _0xf9ef4b, 10, 5)
  )
  _0x5c13fb += this_is_abs(
    0.4302783550295858 - some_method.gtfo(_0xf9ef4b, _0x277f3c, _0x3cef24, 14, 2)
  )
  _0x5c13fb += this_is_abs(
    0.6262803313609467 - some_method.gtfo(_0x4c135d, _0x52d3ed, _0x47edd7, 17, 22)
  )

  if (_0x5c13fb > 0.00001) {
    return null
  }
```

We have 25 point match ( 0 - 24). But the problem is this challenge using some WebGL and do some caculation. I tried to reimplement it and use z3 but didn't succeed. So i looked back to the source and saw the chance to bruteforce it.

```javascript
_0x5c13fb += this_is_abs(
    0.21054889940828397 - some_method.gtfo(_0x52d3ed, _0x3cef24, _0x2ee445, 8, 2)
  )
```

This only take 5 elements so it means < 6.5 milion situations. And after that it only take < 3 elements to bruteforce. This is @dad0qbu script and remember to change return value in script.min.js: 
```javascript
for(i = 0;i < 25;i++) {
     for(j = 0; j < 25;j++) {
	  console.log(i,j)
          if(i != j) for(k = 0;k < 25;k++) {
              if(k != i && k != j) for(l = 0;l < 25;l++) {
                  if(l != i && l != j && l != k) for(m = 0;m < 25;m++) {
                      if(m != i && m != j && m != k && m != l) {
                        var res = _0x344186([0, i, 0, j, 0, 0, 0, 0, k, 0, 0, l, 0, 0, 0, 0, 0, 0, 0, 0, 0, m, 0, 0, 0]);
                            if (res < 0.000001){
                              console.log(i,j,k,l,m,res);
                            }
                      }
                  }
              }
          }
    }
}
```
```javascript
let _0x3cef24 = _0x53c5a8['wtf'](_0x56d6f8[0xb], _0x56d6f8[0x1], _0x56d6f8[0x15]) * 0x19
  , _0x2ee445 = _0x3fbc6b[_0x493e52(0x3bc)](_0x53c5a8['wtf'](_0x56d6f8[0x8], _0x56d6f8[0xb], _0x56d6f8[0x1]), 0x19)
  , _0x52d3ed = _0x3fbc6b[_0x493e52(0x2b2)](_0x53c5a8[_0x493e52(_0x234b5b._0x58a433)](_0x56d6f8[0xb], _0x56d6f8[0x3], _0x56d6f8[0x1]), 0x19)
  , result = 0;
result = _0x3fbc6b[_0x493e52(0x2af)](_0x9b7c28, 0.21054889940828397 - _0x53c5a8['gtfo'](_0x52d3ed, _0x3cef24, _0x2ee445, 0x8, 0x2));
return result;
```
[19, 9, 8, 15, 3, 18, 17, 10, 23, 5, 0, 6, 24, 14, 12, 11, 2, 13, 16, 4, 7, 1, 21, 22, 0]

Flag: ``hitcon{hidden_calculation_through_varying_shader_variables_auto-magical_interpolation_0c4ea0d9d4d9518}``

## penguin and crab

Download challenge we got 3 files: bzImage, initramfs.cpio.gz and run.sh. Take a look on run.sh

```bash
#!/bin/bash

qemu-system-x86_64 \
    -cpu qemu64 \
    -m 4096M \
    -nographic \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on nokaslr" \
    -monitor /dev/null \
    -no-reboot
```
We can see it use qemu to boot up. With `initramfs.cpio.gz`, it will initial file system that is loaded to memory. So at first i try to extract this.

```
gzip -d initramfs.cpio.gz
cpio -idm < initramfs.cpio
```

Reading init bash file, nothing special at all.

```bash
#!/bin/sh

export PATH="/sbin:/usr/sbin:/bin:/usr/bin"
export HOME="/root"
export SHELL="/bin/sh"
export PS1="[🐧🦀] \033[1;32m\u\033[0m:\033[1;34m\w\033[0m\# "

mount -t proc none /proc
mount -t sysfs none /sys
mount -t tmpfs tmpfs /tmp
mount -t devtmpfs none /dev
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts

cat /etc/banner

cd /root

setsid cttyhack setuidgid 0 /bin/sh

poweroff -f
```

But in /root folder there is one special file ``penguin_and_crab.ko``. After finding information about this file, I knew that this is ``kernel object file``. Try to load in and see what it did.

```bash
insmod penguin_and_crab.ko
dmesg
[    4.802732] penguin_and_crab: loading out-of-tree module taints kernel.
[    4.806395] penguin_and_crab: Penguin and Crab initializing...
[    4.806525] penguin_and_crab: Input flag: hitcon{????????????????????????????????????????????????????????????????????????????????????????????}
```
This requires us to input flag that its length is 100. Take out the ``penguin_and_crab.ko`` and start analyzing. This my database if you wanna to take a look [penguin_and_crab.ko.i64](https://github.com/ClownCS/clowncs.github.io/blob/master/content/posts/hitconctf2024/penguin_and_crab.ko.i64). I will summarize the follow of this program.

First, to be clear the flag length is 100 and flag will be packed 4 bytes each so the input array will have 25 elements. 

```C
for ( i = 0LL; i != 25; ++i )
  {
    if ( v2 == (penguin_and_crab::RustOutOfTree *)i )
      goto LABEL_396;
    v32 = __ROL4__(
            __ROL4__(
              __ROL4__(
                __ROL4__(
                  __ROL4__(
                    __ROL4__(
                      __ROL4__(
                        __ROL4__(
                          __ROL4__(
                            __ROL4__(
                              __ROL4__(
                                __ROL4__(
                                  __ROL4__(
                                    __ROL4__(
                                      __ROL4__(
                                        __ROL4__(
                                          __ROL4__(
                                            __ROL4__(
                                              __ROL4__(
                                                __ROL4__(
                                                  __ROL4__(
                                                    __ROL4__(
                                                      __ROL4__(
                                                        __ROL4__(
                                                          __ROL4__(
                                                            __ROL4__(
                                                              __ROL4__(input[i] ^ 0xDEADBEEF, 25) ^ 0x14530451,
                                                              25) ^ 0x14530451,
                                                            25) ^ 0x14530451,
                                                          25) ^ 0x14530451,
                                                        25) ^ 0x14530451,
                                                      25) ^ 0x14530451,
                                                    25) ^ 0x14530451,
                                                  25) ^ 0x14530451,
                                                25) ^ 0x14530451,
                                              25) ^ 0x14530451,
                                            25) ^ 0x14530451,
                                          25) ^ 0x14530451,
                                        25) ^ 0x14530451,
                                      25) ^ 0x14530451,
                                    25) ^ 0x14530451,
                                  25) ^ 0x14530451,
                                25) ^ 0x14530451,
                              25) ^ 0x14530451,
                            25) ^ 0x14530451,
                          25) ^ 0x14530451,
                        25) ^ 0x14530451,
                      25) ^ 0x14530451,
                    25) ^ 0x14530451,
                  25) ^ 0x14530451,
                25) ^ 0x14530451,
              25) ^ 0x14530451,
            25) ^ 0xCAFEBABE;
    input[i] = v32;
    v33 = v193;
    input[i] = seem_sus_array.ptr.pointer.pointer[i] ^ v32;
  }
```

This is the first modify of our flag, and it can be revert by ror back. Now let's move on to the core test, it simply creates a new array taking the first 6 elements which each is created from the result of the multiplication of 2 elements from 0-11 and 6 remain elements from 23->12.

```C
while ( 1 )
  {
    v34 = input[2 * cnt_idx];                   // 1/ just check first < after
    v35 = input[2 * cnt_idx + 1];
    if ( (unsigned int)v34 >= (unsigned int)v35 )
      break;
    v36 = len;
    if ( len != another_sus_array.cap.__0 )
      goto LABEL_112;
    if ( (unsigned __int64)*(_OWORD *)&RNvMs0_NtCslOnzLKEK2s9_5alloc7raw_vecINtB5_6RawVecyE20try_reserve_for_pushCsh0k1DozyW36_16penguin_and_crab(
                                         &another_sus_array,
                                         len) == 0x8000000000000001LL )
    {
      v36 = len;
LABEL_112:
      another_sus_array.ptr.pointer.pointer[v36] = v34 * v35;// array contains value from multiply of two value in input
      v37 = v36 + 1;
      if ( !v37 )
        goto LABEL_395;
      len = v37;
    }
    if ( ++cnt_idx == 6 )
    {
      twensix = 26LL;
      p_another_sus_array = &another_sus_array;
      while ( 1 )                               // jne
      {
        cnt_idx = twensix - 2;
        if ( twensix - 2 >= (unsigned __int64)v2 )
          goto LABEL_398;
        v40 = input[twensix - 3];
        v41 = input[twensix - 2];
        if ( (unsigned int)v41 >= (unsigned int)v40 )// check after < before
        {
          v203[0] = (__int64)&wrong;
          v203[1] = 1LL;
          v203[4] = 0LL;
          v203[2] = (__int64)"/home/wxrdnx/penguin-crab/linux-6.9.3/rust/alloc/raw_vec.rs";
          v203[3] = 0LL;
          v38 = v203;
          goto LABEL_125;
        }
        v42 = len;
        if ( len != another_sus_array.cap.__0 )
          goto LABEL_122;

LABEL_122:
      another_sus_array.ptr.pointer.pointer[v42] = v41 * v40;
      v43 = v42 + 1;
      if ( !v43 )
        goto LABEL_395;
      len = v43;
      goto LABEL_116;                  
```

After that we will need to pass 3 more checks. 


```C
v59 = another_sus_array.ptr.pointer.pointer;
p_another_sus_array = (alloc::raw_vec::RawVec<u64,alloc::alloc::Global> *)len;
v60 = 0LL;
while ( v60 != 12 )                   // first check
{
if ( len == v60 )
  goto LABEL_399;
if ( !mid_element )
  goto LABEL_400;
if ( v45 == v60 )
  goto LABEL_401;
v63 = another_sus_array.ptr.pointer.pointer[v60];
if ( HIDWORD(v63) )
  v61 = v63 / mid_element;
else
  v61 = (unsigned int)v63 / (unsigned int)mid_element;
v62 = v61 == pointer[v60++];
if ( !v62 )                         // first check
{
  v204[0] = (__int64)&wrong;
  v204[1] = 1LL;
  v204[4] = 0LL;
  v204[2] = (__int64)"/home/wxrdnx/penguin-crab/linux-6.9.3/rust/alloc/raw_vec.rs";
  v204[3] = 0LL;
  RNvNtCs48FVigIbjZk_6kernel5print11call_printk(
    &RNvNtNtCs48FVigIbjZk_6kernel5print14format_strings3ERR,
    "penguin_and_crab",
    17LL,
    v204);
  goto LABEL_393;
}
}

...


 while ( v77 != (alloc::raw_vec::RawVec<u64,alloc::alloc::Global> *)((char *)&loc_B + 1) )// second check
  {
    if ( v77 == p_another_sus_array )
      goto LABEL_404;
    if ( !mid_element )
      goto LABEL_405;
    v78 = v59[(_QWORD)v77];
    if ( HIDWORD(v78) )
      v79 = v59[(_QWORD)v77] % mid_element;
    else
      v79 = (unsigned int)v78 % (unsigned int)mid_element;
    v80 = 1LL;
    if ( v79 )
    {
      v81 = 0x56361E32LL;
      do
      {
        if ( (v79 & 1) != 0 )
          v80 = v81 * v80 % 0xE53ACEB5;
        v81 = v81 * v81 % 0xE53ACEB5;
        v82 = v79 < 2;
        v79 >>= 1;
      }
      while ( !v82 );
    }
    if ( v77 == (alloc::raw_vec::RawVec<u64,alloc::alloc::Global> *)v65 )
      goto LABEL_406;
    v62 = v80 == *(&v2->numbers.buf.cap.__0 + (_QWORD)v77);
    v77 = (alloc::raw_vec::RawVec<u64,alloc::alloc::Global> *)((char *)v77 + 1);// second check
    if ( !v62 )
    {
      v205[0] = (__int64)&wrong;
      v205[1] = 1LL;
      v205[4] = 0LL;
      v205[2] = (__int64)"/home/wxrdnx/penguin-crab/linux-6.9.3/rust/alloc/raw_vec.rs";
      v205[3] = 0LL;
      RNvNtCs48FVigIbjZk_6kernel5print11call_printk(
        &RNvNtNtCs48FVigIbjZk_6kernel5print14format_strings3ERR,
        "penguin_and_crab",
        17LL,
        v205);
      goto LABEL_391;
    }
  }



...


v179 = stilll_arrr.ptr.pointer.pointer + 1;
v180 = v45;
v181 = 0uLL;
for ( j = 0LL; j != 32; j += 2LL )    // mid element bit check
{
if ( !v180 )
  goto LABEL_402;
v82 = _bittest((const int *)&mid_element, j);
v183 = v82 * *((_QWORD *)v179 - 1);
v184 = *((_QWORD *)v179 - 2) * v82;
v82 = __CFADD__(__CFADD__(v184, (_QWORD)v181), *((_QWORD *)&v181 + 1));
v185 = __PAIR128__(v183, v184) + v181;
if ( v82 | __CFADD__(v183, *((_QWORD *)&v185 + 1)) )
  goto LABEL_403;
if ( (j | 1) == v45 )
  goto LABEL_402;
v82 = _bittest((const int *)&mid_element, j | 1);
v186 = v82 * *((_QWORD *)v179 + 1);
v187 = *(_QWORD *)v179 * v82;
v82 = __CFADD__(__CFADD__(v187, (_QWORD)v185), *((_QWORD *)&v185 + 1));
v181 = __PAIR128__(v186, v187) + v185;
if ( v82 | __CFADD__(v186, *((_QWORD *)&v181 + 1)) )
  goto LABEL_403;
v179 += 2;
v180 -= 2LL;
}
if ( (unsigned __int64)v181 ^ 0xB3312EC731522288LL | *((_QWORD *)&v181 + 1) ^ 6LL )
{
v206[0] = (__int64)&wrong;
v206[1] = 1LL;
v206[4] = 0LL;
v206[2] = (__int64)"/home/wxrdnx/penguin-crab/linux-6.9.3/rust/alloc/raw_vec.rs";
v206[3] = 0LL;
v188 = v206;
v189 = &RNvNtNtCs48FVigIbjZk_6kernel5print14format_strings3ERR;
}
else
{
v207[0] = (__int64)&correct;
v207[1] = 1LL;
v207[4] = 0LL;
v207[2] = (__int64)"/home/wxrdnx/penguin-crab/linux-6.9.3/rust/alloc/raw_vec.rs";
v207[3] = 0LL;
v188 = v207;
v189 = &RNvNtNtCs48FVigIbjZk_6kernel5print14format_strings6NOTICE;
}
```

As you can see 2 first checks is kinda straight but to solve it we need to know ``mid_element`` which acts as a constant. So last check but it is the first check we need to solve. Look like it really hard to solve but actually it just extract bit from mid_element and multiply with elements in an array. For example if it is 1 so it will take it and add it into sum, if not it doesn't take that. So the problem is understandable now.


```python
def find_combination(arr, target, result=None, start=0):
    if result is None:
        result = []

    if target == 0:
        return True
    if start >= len(arr):
        return False
    
    for i in range(start, len(arr)):
        if arr[i] <= target:
            result.append(arr[i])
            if find_combination(arr, target - arr[i], result, i + 1):
                return True
            result.pop()
    return False

arr = [
    0x38ED550C61366B19,
    0xA368D7F6F944EF95,
    0x7730E544811B003B,
    0x0BA7B915F29478B8,
    0x4CF3C7A1444DDCD5,
    0x6A1EE5D1CB932EDD,
    0x1C653D0FAA75CD04,
    0x5129602CEBB27CD3,
    0x8D3E0DDB822D166C,
    0x7743085C81B563CA,
    0x1FD73D5B1682BEC1,
    0x49CA0C91D932E680,
    0x10AC7806FD7DC9E2,
    0x939CB3D71DC3703E,
    0x3719C10EFED548AF,
    0x091AAD1F7FE14E4B,
    0x8FE8985576B03857,
    0x376937BC0AF64E77,
    0x26190529FD5F0437,
    0x12CF894F2AF71BF3,
    0x22E8F33E31870D59,
    0x6842E8D2ED57A1F1,
    0x189EBE5A06E8334F,
    0x591CEA928108D643,
    0x4914740091A11C11,
    0x3B1A8BB8CD64FAE1,
    0x48009C01B6DC47BA,
    0x6CC80ED5A2D94B80,
    0x3A41F29B470B9346,
    0x000154D52272BF8F,
    0x7E416B359A0655CC,
    0x6858E18B590D1A8F
]

target = 0x6B3312EC731522288
result = []

if find_combination(arr, target, result):
    print("Found a combination:")
    for elem in arr:
        if elem in result:
            print("1", end="")
        else:
            print("0", end="")

```
It will take a while. But we got the result at the end... Remember to reverse my result array because when it extracts bit it will multiply backward with the array because of this i wasted a lot of time.

So the mid element is ``0xBEE66F8F``. With the mid element, 2 checks can be solved now. As you can see this check is actually is modular exponentiation.

```C
if ( HIDWORD(v78) )
  v79 = v59[(_QWORD)v77] % mid_element;
else
  v79 = (unsigned int)v78 % (unsigned int)mid_element;
v80 = 1LL;
if ( v79 )
{
  v81 = 0x56361E32LL;
  do
  {
    if ( (v79 & 1) != 0 )
      v80 = v81 * v80 % 0xE53ACEB5;
    v81 = v81 * v81 % 0xE53ACEB5;
    v82 = v79 < 2;
    v79 >>= 1;
  }
  while ( !v82 );
}
if ( v77 == (alloc::raw_vec::RawVec<u64,alloc::alloc::Global> *)v65 )
  goto LABEL_406;
v62 = v80 == *(&v2->numbers.buf.cap.__0 + (_QWORD)v77);
v77 = (alloc::raw_vec::RawVec<u64,alloc::alloc::Global> *)((char *)v77 + 1);// second check
```

Which is ``(0x56361E32 ^ v79) % 0xE53ACEB5``. This is my bruteforce code to find v79 a.k.a power.

```C++
#include <cstdint>
#include <iostream>

int main() {
  uint32_t base = 0x56361E32;
  uint32_t mod = 0xE53ACEB5;
  uint32_t value[] = {0xA2CC3F37, 0xB8B0E2E6, 0x9DEA4FD6, 0x897DA0D6, 0x52B660E5, 0x7DBCDC09, 0x588E7836, 0x3EA786E5, 0x5BC7BB33, 0xA3959E86, 0xB09E4A8C};

  size_t cur = 1;
  for (uint32_t pow = 1; pow < mod; ++pow) {
    cur = (cur * base) % mod;
    for (size_t i = 0; i < 12; ++i) {
      if (cur == value[i]) {
        printf("%ld: 0x%x\n",i, pow);
      }
    }
  }
  return 0;
}
```
Or you can use **https://www.alpertron.com.ar/DILOG.HTM**

One more check. This check is simple.

```C
v59 = another_sus_array.ptr.pointer.pointer;
p_another_sus_array = (alloc::raw_vec::RawVec<u64,alloc::alloc::Global> *)len;
v60 = 0LL;
while ( v60 != 12 )                   // first check
{
if ( len == v60 )
  goto LABEL_399;
if ( !mid_element )
  goto LABEL_400;
if ( v45 == v60 )
  goto LABEL_401;
v63 = another_sus_array.ptr.pointer.pointer[v60];
if ( HIDWORD(v63) )
  v61 = v63 / mid_element;
else
  v61 = (unsigned int)v63 / (unsigned int)mid_element;
v62 = v61 == pointer[v60++];
if ( !v62 )                         // first check
{
  v204[0] = (__int64)&wrong;
  v204[1] = 1LL;
  v204[4] = 0LL;
  v204[2] = (__int64)"/home/wxrdnx/penguin-crab/linux-6.9.3/rust/alloc/raw_vec.rs";
  v204[3] = 0LL;
  RNvNtCs48FVigIbjZk_6kernel5print11call_printk(
    &RNvNtNtCs48FVigIbjZk_6kernel5print14format_strings3ERR,
    "penguin_and_crab",
    17LL,
    v204);
  goto LABEL_393;
}
}
```

Back to previous we succeeded on recover `v79 = v59[cnt] % mid_element;`. Which use the same array check in this. This check is `v59[cnt] / mid_element == array[cnt]`. Just a simple math right now. 

```python
mid_element = 0xBEE66F8F
arr = [
    mid_element * 0x01BE3B694 + 0x44476065,
    mid_element * 0x00AD42F89 + 0xacd4feca,
    mid_element * 0x1003913B7 + 0xb14d4f2e,
    mid_element * 0x037C23EB4 + 0xa33a5e31,
    mid_element * 0x064C07EF5 + 0xb385631a,
    mid_element * 0x00D7B4785 + 0x192112d0,
    mid_element * 0x049115944 + 0x3c07c8e3,
    mid_element * 0x05241F45E + 0x110cf695,
    mid_element * 0x0829722E9 + 0x28aab06a,
    mid_element * 0x06801CA71 + 0x19c05014,
    mid_element * 0x0165020CF + 0xb88df870,
    mid_element * 0x0E45F7AB1 + 0x781aa68a ]
```

But the problem is how can we find two number that multiply equal to that. Now factordb help us a hand http://factordb.com/. From this we are completely able to get the flag but remember to reverse last 6 pairs in that arrays :D. The final step is ror back.

```python
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def decrypt(x: int) -> int:
    max_bits = 32
    x ^= 0xCAFEBABE
    for _ in range(26):
        x = (ror(x, 25,max_bits)) ^ 0x14530451
    return ror(x, 25,max_bits) ^ 0xDEADBEEF

enc = [0x1726ef35, 0xe5f661ed, 0x1a6a6775, 0x4e41fced, 0xcf3e4a8b, 0xec046a15, 0x2fbac147, 0xdf039fdb, 0x4bf4b8cb, 0xfd384d3f, 0x1a982f89, 0x60c5ee83, 0xBEE66F8F, 0xf173ba59, 0xb48f3291, 0xff67b683, 0x10ad79db, 0xbb5d3b41, 0x69f84673, 0xda5d8a77, 0x722a4837, 0x9f70beb7, 0x627cf8a1, 0xbb8bfaf5, 0x4a5fcd03]
arr = [0xAEC4F08C, 0x642C04AC, 0xA3607854, 0x2D393934, 0x8E2C4F5A, 0xDDD67D14, 0x7E005496, 0x3ED14A02, 0xA56A772, 0x466A4076, 0xD3A352A9, 0x495E93E3, 0x67C44ADF, 0x3AEBE5BA, 0xED850DA8, 0xD4B77198, 0x51BDB6B2, 0x3A5F2448, 0x807889CA, 0x5B9D4D6E, 0x8320EFD6, 0x9E68E874, 0xBA7FBEA1, 0x827BC7E4, 0x129F824A]

flag = b''
for i in range(25):
    flag += decrypt(enc[i] ^ arr[i]).to_bytes(4, 'big')
print(flag)  
```

Flag: ``hitcon{<https://www.youtube.com/watch?v=FrX0ZfX8Dqs>&&<https://www.youtube.com/watch?v=LDU_Txk06tM>}``
