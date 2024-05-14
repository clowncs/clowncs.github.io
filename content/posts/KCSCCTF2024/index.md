---
weight: 1
title: "KCSC CTF 2024"
date: 2024-05-14
lastmod: 2024-05-14
draft: false
author: "ClownCS"
authorLink: "https://clowncs.github.io"
description: "Solutions for some reverse challenges in KCSC CTF 2024"
tags: ["RE", "2024"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---
Solutions for some reverse challenges in KCSC CTF 2024

<!--more-->

# RE
Mình có xin được đề KCSC nên sẽ bắt đầu ngồi làm từ lúc giải bắt đầu cho tới khi end xem mình có thể làm được bao nhiêu câu.

## Fk3
Tải chương trình về và đọc thử hàm main.

```C=
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  unsigned int v4; // eax
  __int64 v5; // rdx
  __int64 v6; // r8
  char v8[256]; // [rsp+30h] [rbp-D18h] BYREF
  char Str[1024]; // [rsp+130h] [rbp-C18h] BYREF
  CHAR String2[1024]; // [rsp+530h] [rbp-818h] BYREF
  CHAR String1[1024]; // [rsp+930h] [rbp-418h] BYREF

  Str[0] = 0xDF;
  Str[1] = 69;
  Str[2] = 67;
  Str[3] = 49;
  Str[4] = -122;
  Str[5] = 38;
  Str[6] = 116;
  Str[7] = -97;
  Str[8] = -87;
  Str[9] = 118;
  Str[10] = -115;
  Str[11] = -86;
  Str[12] = -108;
  Str[13] = 116;
  Str[14] = -73;
  Str[15] = 46;
  Str[16] = -98;
  Str[17] = -94;
  Str[18] = 20;
  Str[19] = 5;
  Str[20] = 109;
  Str[21] = -87;
  Str[22] = -34;
  Str[23] = -89;
  Str[24] = 80;
  Str[25] = 57;
  Str[26] = 17;
  memset(&Str[27], 0, 0x3E5ui64);
  sub_1400010E0("[+] Input flag: ", argv, envp);
  sub_1400011B0("%s", String1);
  v3 = strlen(::Str);
  sub_140001880(v8, ::Str, v3);
  v4 = strlen(Str);
  RC4(v8, Str, v4, String2);
  if ( lstrcmpA(String1, String2) )
    sub_1400010E0("\nWrong!", v5, v6);
  else
    sub_1400010E0("Correct!", v5, v6);
  return 0;
}
```

Nhìn sơ qua thì có thể thấy nó nhận flag của chúng ta sau đó mã hóa RC4 chuỗi ``Str`` sau đó compare với flag bằng hàm ``lstrcmpA``. Và tất nhiên sẽ không có gì để nói nếu bài này lại dễ như vậy. Tuy nhiên khi thử debug thì mình nhận ra mình nhận fake flag. 

![image](https://hackmd.io/_uploads/r1bLAzg7A.png)

Anti debug ? Lúc này mình xref trace ngược về những hàm mà call chuỗi ``Str`` tức key. 

```C
__int64 antidebug()
{
  if ( !*(_BYTE *)(qword_7FF7ACCD5670 + 2) )
  {
    Str[1] |= 1u;
    Str[2] |= 1u;
    Str[3] |= 1u;
    Str[4] |= 1u;
  }
  return 0i64;
}
```

Đặt breakpoint tại hàm check sau đó. Mình có được key đúng là ``FA++!``. Tưởng như thế đã là xong mình dùng key đó và giải mã mảng lúc đầu. Vẫn không ra ??? Và mình để ý rằng với input như nào thì output của hàm ``lstrcmpA`` luôn bằng 0 tức là hai chuỗi bằng nhau ?? 

Lúc này mình đã đi tới ngõ cụt. Mình liền đi xem các hàm còn lại xem có gì sus không.

```C
__int64 SUS()
{
  HMODULE ModuleHandleA; // [rsp+20h] [rbp-78h]
  unsigned int *i; // [rsp+28h] [rbp-70h]
  _QWORD *v3; // [rsp+30h] [rbp-68h]
  __int64 (__fastcall **lpAddress)(__int64, __int64); // [rsp+38h] [rbp-60h]
  DWORD flOldProtect; // [rsp+78h] [rbp-20h] BYREF

  ModuleHandleA = GetModuleHandleA(0i64);
  for ( i = (unsigned int *)((char *)ModuleHandleA
                           + (unsigned int)*(_QWORD *)((char *)ModuleHandleA + *((int *)ModuleHandleA + 15) + 144));
        i[3];
        i += 5 )
  {
    if ( LoadLibraryA((LPCSTR)ModuleHandleA + i[3]) )
    {
      v3 = (_QWORD *)((char *)ModuleHandleA + *i);
      lpAddress = (__int64 (__fastcall **)(__int64, __int64))((char *)ModuleHandleA + i[4]);
      while ( *v3 )
      {
        if ( !strcmp((const char *)ModuleHandleA + *v3 + 2, "lstrcmpA") )
        {
          flOldProtect = 0;
          VirtualProtect(lpAddress, 8ui64, 4u, &flOldProtect);
          *lpAddress = riel_func;
        }
        ++v3;
        ++lpAddress;
      }
    }
  }
  return 0i64;
}
```

Và rồi mình tìm được hàm này. Giải thích sơ qua hàm này sẽ load các thư viện và so sánh với ``lstrcmpA``. Nếu đúng gán ``lstrcmpA`` bằng hàm ``riel_func``.

```C
__int64 __fastcall riel_func(__int64 a1, __int64 a2)
{
  int i; // [rsp+20h] [rbp-128h]
  char Str[128]; // [rsp+30h] [rbp-118h] BYREF
  char v5[128]; // [rsp+B0h] [rbp-98h] BYREF

  qmemcpy(Str, "fM", 2);
  Str[2] = 12;
  Str[3] = -95;
  Str[4] = 86;
  Str[5] = 63;
  Str[6] = 43;
  Str[7] = -67;
  Str[8] = 78;
  Str[9] = 97;
  Str[10] = 106;
  Str[11] = -114;
  Str[12] = 73;
  Str[13] = 81;
  Str[14] = 61;
  Str[15] = -121;
  Str[16] = 114;
  Str[17] = 124;
  Str[18] = 54;
  Str[19] = -123;
  Str[20] = 69;
  Str[21] = 122;
  Str[22] = 104;
  Str[23] = -67;
  Str[24] = 75;
  Str[25] = 98;
  Str[26] = 62;
  Str[27] = -37;
  Str[28] = 114;
  Str[29] = 102;
  Str[30] = 58;
  Str[31] = -112;
  Str[32] = 72;
  Str[33] = 81;
  Str[34] = 1;
  Str[35] = -52;
  Str[36] = 115;
  Str[37] = 78;
  Str[38] = 31;
  Str[39] = -97;
  memset(&Str[40], 0, 0x58ui64);
  memset(v5, 0, sizeof(v5));
  for ( i = 0; i < strlen(Str); ++i )
    v5[i] = *(_BYTE *)(a2 + i % 4) ^ Str[i];
  return 0i64;
}
```
Lúc này thì mọi thứ đã rõ. Bản thân hàm này luôn ``return 0``. Đó là lí do vì sao khi debug nếu nhập input gì cũng correct. Hiểu được chương trình làm gì mình debug và lấy flag thôi.

![image](https://hackmd.io/_uploads/HyYdkQe70.png)


Flag: ``KCSC{1t_co5ld_be_right7_fla9_here_^.^@@}``


## REXRUST

Một bài rev rust tuy nhiên thì cũng khá đơn giản. Chương trình đọc flag từ ``flag.txt``. Và sẽ mã hóa qua 4 phase sau đó ghi ra ``flag.enc``.


PHASE 1:

```C
void __cdecl revsrust::phase1::hff4818a749ae18af(_mut__u8_ data)
{
  core::ops::range::Range<usize> v1; // rdi
  usize v2; // [rsp+0h] [rbp-98h]
  usize v3; // [rsp+18h] [rbp-80h]
  u8 v4; // [rsp+27h] [rbp-71h]
  usize v5; // [rsp+28h] [rbp-70h]
  unsigned __int64 v6; // [rsp+30h] [rbp-68h]
  core::ops::range::Range<usize> v8; // [rsp+58h] [rbp-40h] BYREF
  core::option::Option<usize> v9; // [rsp+68h] [rbp-30h]
  _mut__u8_ v10; // [rsp+78h] [rbp-20h]
  __int64 v11; // [rsp+88h] [rbp-10h]
  u8 v12; // [rsp+97h] [rbp-1h]

  v10 = data;
  v1.end = data.length >> 1;
  v1.start = 0LL;
  v8 = _$LT$I$u20$as$u20$core..iter..traits..collect..IntoIterator$GT$::into_iter::h8fa0f7e2a7257375(v1);
  while ( 1 )
  {
    v9 = core::iter::range::_$LT$impl$u20$core..iter..traits..iterator..Iterator$u20$for$u20$core..ops..range..Range$LT$A$GT$$GT$::next::h9b7c30fb7e58cb7b(&v8);
    if ( !*(_QWORD *)v9.gap0 )
      break;
    v6 = *(_QWORD *)&v9.gap0[8];
    v11 = *(_QWORD *)&v9.gap0[8];
    if ( *(_QWORD *)&v9.gap0[8] >= data.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    v4 = data.data_ptr[*(_QWORD *)&v9.gap0[8]];
    v12 = v4;
    v5 = data.length - 1;
    if ( !data.length )
      core::panicking::panic::hee69a8315e4031d6();
    v3 = v5 - *(_QWORD *)&v9.gap0[8];
    if ( v5 < *(_QWORD *)&v9.gap0[8] )
      core::panicking::panic::hee69a8315e4031d6();
    if ( v3 >= data.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    if ( *(_QWORD *)&v9.gap0[8] >= data.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    data.data_ptr[*(_QWORD *)&v9.gap0[8]] = data.data_ptr[v3];
    v2 = data.length - 1 - v6;
    if ( data.length - 1 < v6 )
      core::panicking::panic::hee69a8315e4031d6();
    if ( v2 >= data.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    data.data_ptr[v2] = v4;
  }
}
```

Phase 1 đơn giản là đảo ngược flag.


PHASE 2:

```C
void __cdecl revsrust::phase2::hf6a223748e1b24a0(_mut__u8_ data)
{
  u8 v1; // [rsp+17h] [rbp-71h]
  usize v2; // [rsp+48h] [rbp-40h]
  usize i; // [rsp+68h] [rbp-20h]

  for ( i = 0LL; i < data.length; i += 2LL )
  {
    v2 = i + 1;
    if ( i == -1LL )
      core::panicking::panic::hee69a8315e4031d6();
    if ( v2 >= data.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    if ( i + 1 >= data.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    if ( i >= data.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    v1 = data.data_ptr[i] & 0xF | data.data_ptr[i + 1] & 0xF0;
    data.data_ptr[i] = data.data_ptr[v2] & 0xF | data.data_ptr[i] & 0xF0;
    if ( i + 1 >= data.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    data.data_ptr[i + 1] = v1;
    if ( i >= 0xFFFFFFFFFFFFFFFELL )
      core::panicking::panic::hee69a8315e4031d6();
  }
}
```

Phase 2 có thể implement như sau

```python
for i in range(0, len(data), 2):
    data[i], data[i + 1] = (data[i + 1] & 0xf) | (data[i] & 0xf0), (data[i] & 0xf) | (data[i + 1] & 0xf0)
```

PHASE 3
```C
void __cdecl revsrust::phase3::h3b700fce28ff291d(_mut__u8_ data)
{
  u8 v1; // si
  u8 v2; // dl
  u8 v3; // [rsp+1Fh] [rbp-89h]
  usize v4; // [rsp+20h] [rbp-88h]
  u8 v5; // [rsp+2Fh] [rbp-79h]
  usize v6; // [rsp+30h] [rbp-78h]
  usize v7; // [rsp+38h] [rbp-70h]
  _mut__u8_ v8; // [rsp+40h] [rbp-68h]
  core::ops::range::Range<usize> v9; // [rsp+68h] [rbp-40h] BYREF
  core::option::Option<usize> v10; // [rsp+78h] [rbp-30h]
  _mut__u8_ v11; // [rsp+88h] [rbp-20h]
  __int64 v12; // [rsp+98h] [rbp-10h]
  u8 v13; // [rsp+A4h] [rbp-4h]
  u8 v14; // [rsp+A5h] [rbp-3h]
  u8 v15; // [rsp+A6h] [rbp-2h]
  u8 v16; // [rsp+A7h] [rbp-1h]

  v8 = data;
  v11 = data;
  if ( data.length < 2 )
    core::panicking::panic::hee69a8315e4031d6();
  data.data_ptr = 0LL;
  data.length -= 2LL;
  v9 = _$LT$I$u20$as$u20$core..iter..traits..collect..IntoIterator$GT$::into_iter::h8fa0f7e2a7257375((core::ops::range::Range<usize>)data);
  while ( 1 )
  {
    v10 = core::iter::range::_$LT$impl$u20$core..iter..traits..iterator..Iterator$u20$for$u20$core..ops..range..Range$LT$A$GT$$GT$::next::h9b7c30fb7e58cb7b(&v9);
    if ( !*(_QWORD *)v10.gap0 )
      break;
    v7 = *(_QWORD *)&v10.gap0[8];
    v12 = *(_QWORD *)&v10.gap0[8];
    if ( *(_QWORD *)&v10.gap0[8] >= v8.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    v5 = v8.data_ptr[*(_QWORD *)&v10.gap0[8]];
    v6 = *(_QWORD *)&v10.gap0[8] + 2LL;
    if ( *(_QWORD *)&v10.gap0[8] >= 0xFFFFFFFFFFFFFFFELL )
      core::panicking::panic::hee69a8315e4031d6();
    if ( v6 >= v8.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    v1 = v8.data_ptr[v6];
    v15 = v8.data_ptr[*(_QWORD *)&v10.gap0[8]];
    v16 = v1;
    if ( *(_QWORD *)&v10.gap0[8] >= v8.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    v8.data_ptr[*(_QWORD *)&v10.gap0[8]] = v5 - v1;
    v4 = v7 + 2;
    if ( __CFADD__(v7, 2LL) )
      core::panicking::panic::hee69a8315e4031d6();
    if ( v4 >= v8.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    v3 = v8.data_ptr[v4];
    if ( v7 >= v8.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    v2 = v8.data_ptr[v7];
    v13 = v8.data_ptr[v4];
    v14 = v2;
    if ( v7 + 2 >= v8.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    v8.data_ptr[v7 + 2] = v3 - v2;
  }
}
```

Phase 3 thì

```python
for i in range(len(data) - 2):
    data[i] = (data[i] - data[i + 2]) & 0xff
    data[i + 2] = (data[i + 2] -  data[i]) & 0xff
```

PHASE 4:
```C
void __cdecl revsrust::phase4::h4b371456b6af0137(_mut__u8_ data)
{
  u8 *data_ptr; // [rsp+38h] [rbp-80h]
  u32 v2; // [rsp+4Ch] [rbp-6Ch]
  rand::rngs::thread::ThreadRng self; // [rsp+50h] [rbp-68h] BYREF
  core::ops::range::Range<usize> v4; // [rsp+58h] [rbp-60h]
  core::ops::range::Range<usize> v5; // [rsp+68h] [rbp-50h] BYREF
  core::option::Option<usize> v6; // [rsp+78h] [rbp-40h]
  _mut__u8_ v7; // [rsp+88h] [rbp-30h]
  u32 v8; // [rsp+ACh] [rbp-Ch]
  __int64 v9; // [rsp+B0h] [rbp-8h]

  data_ptr = data.data_ptr;
  v7 = data;
  self.rng.ptr.pointer = rand::rngs::thread::thread_rng::h616f5a4f3d25fa48().rng.ptr.pointer;
  v2 = rand::rng::Rng::gen::h3adc539b43e4e5da(&self);
  v8 = v2;
  v4.start = 0LL;
  v4.end = data.length;
  data.data_ptr = 0LL;
  v5 = _$LT$I$u20$as$u20$core..iter..traits..collect..IntoIterator$GT$::into_iter::h8fa0f7e2a7257375((core::ops::range::Range<usize>)data);
  while ( 1 )
  {
    v6 = core::iter::range::_$LT$impl$u20$core..iter..traits..iterator..Iterator$u20$for$u20$core..ops..range..Range$LT$A$GT$$GT$::next::h9b7c30fb7e58cb7b(&v5);
    if ( !*(_QWORD *)v6.gap0 )
      break;
    v9 = *(_QWORD *)&v6.gap0[8];
    if ( *(_QWORD *)&v6.gap0[8] >= data.length )
      core::panicking::panic_bounds_check::h11601ba3567ad740();
    data_ptr[*(_QWORD *)&v6.gap0[8]] ^= HIBYTE(v2) ^ BYTE2(v2) ^ BYTE1(v2) ^ v2;
  }
  core::ptr::drop_in_place$LT$rand..rngs..thread..ThreadRng$GT$::h46c61e1ef1922a5a(&self);
}
```

Phase 4 thì chỉ là gen ra ramdom 32 bit number sau đó xor với flag. Có những dữ kiện như trên thì việc giải chỉ cần dùng z3.

```python
from z3 import *
with open("flag.enc", "rb") as f:
    cmp=f.read()

data = [BitVec(f'data_{i}', 32) for i in range(len(cmp))]

solver = Solver()

for i in range(len(data)):
    solver.add(data[i] > 32)
    solver.add(data[i] < 127)

flag = list(reversed(data))

for i in range(0, len(flag), 2):
    flag[i], flag[i + 1] = (flag[i + 1] & 0xf) | (flag[i] & 0xf0), (flag[i] & 0xf) | (flag[i + 1] & 0xf0)

for i in range(len(flag) - 2):
    flag[i] = (flag[i] - flag[i + 2]) & 0xff
    flag[i + 2] = (flag[i + 2] -  flag[i]) & 0xff


xor_key = BitVec('xor_key', 32)

for i in range(len(flag)):
    flag[i] ^= ((xor_key >> 0) & 0xff) ^ ((xor_key >> 8) & 0xff) ^ ((xor_key >> 16) & 0xff) ^ ((xor_key >> 24) & 0xff)


for i in range(len(cmp)):
    solver.add(flag[i] == cmp[i])

if solver.check() == sat:
    model = solver.model()
    original_data_values = [chr(model[data[i]].as_long()) for i in range(len(cmp))]
    print("".join(original_data_values))
```

Flag: ``KCSC{r3v3rs3_rust_1s_funny_4nd_34sy_227da29931351}``

## BEHIND THE SCENE
under maintenance
