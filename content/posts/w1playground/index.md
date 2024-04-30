---
weight: 1
title: "W1 Playground"
date: 2024-03-06
lastmod: 2024-03-06
draft: false
author: "ClownCS"
authorLink: "https://clowncs.github.io"
description: "Solutions for all reverse challenges in W1"
tags: ["RE", "Wargame","2024"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---
Solutions for all reverse challenges in W1

<!--more-->

# RE
## SUDOKU
A small game for warm-up.

Author: dream02

### Solution:
Đây là bài warmup nên chỉ cần nhìn kĩ là có thể giải được. Script của mình (pass giải nén là flag bài 2):

[script](https://drive.google.com/file/d/1s7jbRTN4VMyfspbRpqUGKtj9M-WM3WnY/view?usp=sharing)

## EBPF
Note: Run with sudo (not infected).

Author: Jinn

### Solution
Đây là chương trình ebpf, để tiếp cận được tới chương trình chính thì không thể chỉ đọc bằng ida.

> The Just-in-Time (JIT) compilation step translates the generic bytecode of the program into the machine specific instruction set to optimize execution speed of the program. This makes eBPF programs run as efficiently as natively compiled kernel code or as code loaded as a kernel module.

Có hai cách đó là debug tới khi thấy bytecode của chương trình sau đó dùng ``objdump`` để dump ra instructions. Ở đây thì mình sử dụng ``bpftool`` để có thể disassemble instructions của chương trình.

Đầu tiên reverse sơ qua flow chương trình chưa tính mạch chính là của ebpf, ta thấy chương trình yêu cầu nhập flag độ dài 56 sau đó load từng 4 kí tự vào ``bpf_map_update_elem()``

```C
for ( i = 0; v19 > i; i += 4 )
{
    key = 0;
    if ( bpf_map_update_elem(fd, &key, &input[i], BPF_ANY) )
    __assert_fail(
        "bpf_map_update_elem(map_fd, &key, &buf[i], BPF_ANY) == 0",
        "chall.c",
        0x103u,
        "chall");
    key = 1;
    if ( bpf_map_update_elem(fd, &key, &input[i + 1], BPF_ANY) )
    __assert_fail(
        "bpf_map_update_elem(map_fd, &key, &buf[i + 1], BPF_ANY) == 0",
        "chall.c",
        0x105u,
        "chall");
    key = 2;
    if ( bpf_map_update_elem(fd, &key, &input[i + 2], BPF_ANY) )
    __assert_fail(
        "bpf_map_update_elem(map_fd, &key, &buf[i + 2], BPF_ANY) == 0",
        "chall.c",
        0x107u,
        "chall");
    key = 3;
    if ( bpf_map_update_elem(fd, &key, &input[i + 3], BPF_ANY) )
    __assert_fail(
        "bpf_map_update_elem(map_fd, &key, &buf[i + 3], BPF_ANY) == 0",
        "chall.c",
        0x109u,
        "chall");
    trigger_bpf_program();
    key = 0;                      // save
    if ( bpf_map_lookup_elem(fd, &key, &input[i]) )
    __assert_fail("bpf_map_lookup_elem(map_fd, &key, &buf[i]) == 0", "chall.c", 0x10Eu, "chall");
    key = 1;
    if ( bpf_map_lookup_elem(fd, &key, &input[i + 1]) )
    __assert_fail("bpf_map_lookup_elem(map_fd, &key, &buf[i + 1]) == 0", "chall.c", 0x110u, "chall");
    key = 2;
    if ( bpf_map_lookup_elem(fd, &key, &input[i + 2]) )
    __assert_fail("bpf_map_lookup_elem(map_fd, &key, &buf[i + 2]) == 0", "chall.c", 0x112u, "chall");
    key = 3;
    if ( bpf_map_lookup_elem(fd, &key, &input[i + 3]) )
    __assert_fail("bpf_map_lookup_elem(map_fd, &key, &buf[i + 3]) == 0", "chall.c", 0x114u, "chall");
}
if ( !memcmp(input, &enc, 0xE0uLL) )
    puts("That's flag!");
else
    puts("Nope!");
```
Sau khi được thực hiện biến đổi thì nó check với mảng ``enc``. Nếu đúng thì sẽ in ra ``That's flag!``. Quay lại với mạch chính là làm sao để disassemble được instructions thì mình đặt breakpoint sau khi chương trình chạy hàm ``bpf_load_program``.

```C
optval = bpf_load_program(1LL, &v22, 133LL, &off_556EE4F7A0D6, 0LL, &bpf_log_buf, 0xFFFFFFLL);
if ( optval >= 0 )
```

Trước khi debug thì kiểm tra xem có những chương trình ebpf nào đang chạy bằng ``sudo bpftool prog``

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/c6d7793b-4fa1-4eac-9af2-f9d68d8e5cc0)

Sau đó bắt đầu debug, ta thấy được có thêm một chương trình ``id : 14``, đó là chương trình ta đang cần tìm, dump disassemble code của chương trình nó bằng ``sudo bpftool prog dump xlated id 14``

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/83f82599-98f5-4b5c-8dcb-d4952a0c35b2)

```asm
0: (bf) r9 = r1
1: (18) r1 = map[id:2]
3: (bf) r2 = r10
4: (07) r2 += -4
5: (62) *(u32 *)(r10 -4) = 0
6: (07) r1 += 272
7: (61) r0 = *(u32 *)(r2 +0)
8: (35) if r0 >= 0x100 goto pc+3
9: (67) r0 <<= 3
10: (0f) r0 += r1
11: (05) goto pc+1
12: (b7) r0 = 0
13: (15) if r0 == 0x0 goto pc+14
14: (61) r5 = *(u32 *)(r0 +0)
15: (63) *(u32 *)(r10 -20) = r5
16: (18) r1 = map[id:2]
18: (bf) r2 = r10
19: (07) r2 += -4
20: (62) *(u32 *)(r10 -4) = 1
21: (07) r1 += 272
22: (61) r0 = *(u32 *)(r2 +0)
23: (35) if r0 >= 0x100 goto pc+3
24: (67) r0 <<= 3
25: (0f) r0 += r1
26: (05) goto pc+1
27: (b7) r0 = 0
28: (15) if r0 == 0x0 goto pc+14
29: (61) r5 = *(u32 *)(r0 +0)
30: (63) *(u32 *)(r10 -24) = r5
31: (18) r1 = map[id:2]
33: (bf) r2 = r10
34: (07) r2 += -4
35: (62) *(u32 *)(r10 -4) = 2
36: (07) r1 += 272
37: (61) r0 = *(u32 *)(r2 +0)
38: (35) if r0 >= 0x100 goto pc+3
39: (67) r0 <<= 3
40: (0f) r0 += r1
41: (05) goto pc+1
42: (b7) r0 = 0
43: (15) if r0 == 0x0 goto pc+14
44: (61) r5 = *(u32 *)(r0 +0)
45: (63) *(u32 *)(r10 -28) = r5
46: (18) r1 = map[id:2]
48: (bf) r2 = r10
49: (07) r2 += -4
50: (62) *(u32 *)(r10 -4) = 3
51: (07) r1 += 272
52: (61) r0 = *(u32 *)(r2 +0)
53: (35) if r0 >= 0x100 goto pc+3
54: (67) r0 <<= 3
55: (0f) r0 += r1
56: (05) goto pc+1
57: (b7) r0 = 0
58: (15) if r0 == 0x0 goto pc+96
59: (61) r5 = *(u32 *)(r0 +0)
60: (63) *(u32 *)(r10 -32) = r5
61: (61) r0 = *(u32 *)(r10 -20)
62: (61) r1 = *(u32 *)(r10 -24)
63: (61) r2 = *(u32 *)(r10 -28)
64: (61) r3 = *(u32 *)(r10 -32)
65: (af) r0 ^= r1
66: (5f) r2 &= r3
67: (0f) r0 += r2
68: (57) r0 &= 255
69: (63) *(u32 *)(r10 -36) = r0
70: (61) r0 = *(u32 *)(r10 -20)
71: (61) r2 = *(u32 *)(r10 -28)
72: (af) r2 ^= r3
73: (af) r0 ^= r1
74: (0f) r0 += r2
75: (57) r0 &= 255
76: (63) *(u32 *)(r10 -48) = r0
77: (61) r0 = *(u32 *)(r10 -20)
78: (61) r2 = *(u32 *)(r10 -28)
79: (bf) r4 = r0
80: (1f) r4 -= r2
81: (2f) r2 *= r3
82: (af) r4 ^= r2
83: (0f) r0 += r1
84: (bf) r5 = r0
85: (bf) r6 = r0
86: (67) r5 <<= 5
87: (57) r5 &= 255
88: (57) r6 &= 255
89: (77) r6 >>= 3
90: (4f) r5 |= r6
91: (af) r4 ^= r5
92: (57) r4 &= 255
93: (63) *(u32 *)(r10 -40) = r4
94: (61) r0 = *(u32 *)(r10 -20)
95: (61) r2 = *(u32 *)(r10 -28)
96: (bf) r4 = r1
97: (2f) r4 *= r3
98: (0f) r1 += r2
99: (af) r4 ^= r1
100: (0f) r0 += r2
101: (bf) r5 = r0
102: (bf) r6 = r0
103: (67) r5 <<= 4
104: (57) r5 &= 255
105: (57) r6 &= 255
106: (77) r6 >>= 4
107: (4f) r5 |= r6
108: (af) r4 ^= r5
109: (57) r4 &= 255
110: (63) *(u32 *)(r10 -44) = r4
111: (18) r1 = map[id:2]
113: (62) *(u32 *)(r10 -12) = 0
114: (bf) r2 = r10
115: (07) r2 += -12
116: (61) r5 = *(u32 *)(r10 -36)
117: (7b) *(u64 *)(r10 -8) = r5
118: (bf) r3 = r10
119: (07) r3 += -8
120: (b7) r4 = 0
121: (85) call array_map_update_elem#175408
122: (18) r1 = map[id:2]
124: (62) *(u32 *)(r10 -12) = 1
125: (bf) r2 = r10
126: (07) r2 += -12
127: (61) r5 = *(u32 *)(r10 -40)
128: (7b) *(u64 *)(r10 -8) = r5
129: (bf) r3 = r10
130: (07) r3 += -8
131: (b7) r4 = 0
132: (85) call array_map_update_elem#175408
133: (18) r1 = map[id:2]
135: (62) *(u32 *)(r10 -12) = 2
136: (bf) r2 = r10
137: (07) r2 += -12
138: (61) r5 = *(u32 *)(r10 -44)
139: (7b) *(u64 *)(r10 -8) = r5
140: (bf) r3 = r10
141: (07) r3 += -8
142: (b7) r4 = 0
143: (85) call array_map_update_elem#175408
144: (18) r1 = map[id:2]
146: (62) *(u32 *)(r10 -12) = 3
147: (bf) r2 = r10
148: (07) r2 += -12
149: (61) r5 = *(u32 *)(r10 -48)
150: (7b) *(u64 *)(r10 -8) = r5
151: (bf) r3 = r10
152: (07) r3 += -8
153: (b7) r4 = 0
154: (85) call array_map_update_elem#175408
155: (b7) r0 = 0
156: (95) exit
```

Có thể thấy nó có liên quan tới ``map[id:2]``, ta có thể xem giá trị nó là gì bằng ``sudo bpftool map dump id 2``, tuy nhiên lúc này tất cả đều là 0. Lý do là ta phải debug qua hàm ``bpf_map_update_elem()``, sau đó ta thấy nó load 4 kí tự vào chương trình.

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/c4cb193f-a93c-4c9f-aebd-7b77a810b16a)

Sau đó, nó được lưu lại mảng ``input`` sau khi thực hiện chương trình.

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/da9c06b2-0c62-4b3b-b7b8-4209ce15e955)

Vậy thì lúc này ta đã hiểu sơ nó thực hiện nhận và cần biết nó làm gì đó để có thể kiếm được flag. Quay lại với đống disassmble instructions, ta lấy ra được và thực hiện reverse. Từ dòng đầu tới vòng 60 ta thấy chương trình nhận 4 giá trị từ chương trình gốc sau đó lưu vào stack với offset là 20->32. Sau đó thực hiện biến đổi và lưu lại 4 giá trị đó vào stack với offset từ 36->48 và trả về chương trình gốc. Vậy thì cụ thể nó đã biến đổi ra sao, ta sẽ bắt đầu từ dòng 65 đổ đi. Đây là note của mình cách nó implement

```asm
r0 ^= r1
r2 &= r3
r0 += r2
r0 &= 255

-> ((r0 ^ r1 ) + (r2 & r3)) & 255 // first element

r2 ^= r3
r0 ^= r1
r0 += r2
r0 &= 255

-> ((r0 ^ r1) + (r2 ^ r3) & 255) // fourth element

r4 = r0
r4 -= r2
r2 *= r3
r4 ^= r2
r0 += r1
r5 = r0
r6 = r0
r5 <<= 5
r5 &= 255
r6 &= 255
r6 >>= 3
r5 |= r6
r4 ^= r5
r4 &= 255

-> r4 = ((r0 - r2) ^ (r2 * r3))
-> ((((r0 + r1) << 5 ) & 255) | (((r0+r1) & 255) >> 3))
-> ((((r0 - r2) ^ (r2 * r3)) ^ ((((r0 + r1) << 5 ) & 255) | (((r0+r1) & 255) >> 3))) & 255) // second element

r4 = r1
r4 *= r3
r1 += r2
r4 ^= r1
r0 += r2
r5 = r0
r6 = r0
r5 <<= 4
r5 &= 255
r6 &= 255
r6 >>= 4
r5 |= r6
r4 ^= r5
r4 &= 255

-> r4 = ((r1 * r3) ^ (r1 + r2))
-> ((((r0 + r2) << 4 ) & 255) | (((r0+r2) & 255) >> 4))
-> (((((r1 * r3) ^ (r1 + r2)) ^ ((( (r0 + r2) << 4 ) & 255) | (((r0+r2) & 255) >> 4)))) & 255) // third element
```

Như thế thì ta có thể thấy đây là hệ phương trình 4 ẩn. Lúc này quá rõ ràng rồi ta chỉ cần xài z3 để recover mảng enc 4 kí tự một. Đây là script của mình (pass giải nén là flag bài này):

[script](https://drive.google.com/file/d/1s7jbRTN4VMyfspbRpqUGKtj9M-WM3WnY/view?usp=sharing)

## Shadows of Encryption

Một bài mới do anh **Jinn** ra nên mình quyết định sẽ update lên blog luôn vì sau này chắc hẳn cần để nhìn lại. Tải file về và nhận ra đây là rust và tệ hơn là rust bị stripped, mình như muốn treo cổ vì trước giờ mình rất yếu khi đụng golang hay rust. Nhưng chuyện gì đến cũng phải đến, lets go...

Như mọi lần thì mình sẽ bắt đầu với việc chạy thử xem file làm gì.

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/17feb8b2-ad0e-4c1b-8cf6-097f32d36676)

Hmm có vẻ bị lỗi gì đó mình bắt đầu đi tìm kiếm tại sao lại bị lỗi như trên. Vậy là nó k thể đọc được file nào đó. Tới đây thì việc tiếp theo là mở ida và analyze. Các bạn hãy xài file [res.i64](/content/posts/w1playground/res.i64) vì mình đã khôi phục gần như tất cả các hàm và có comment. Vậy là chương trình cần đọc file ``censored.png`` 

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/d26a1bc6-03f5-413d-be4a-b6094a3d32bf)

Tạo một file ảnh ``censored.png`` bất kì ở đây mình tạo như sau

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/ce18247d-e8ea-46a2-be34-96bb76aacba8)

Tiếp tục debug thì mình phát hiện giá trị mà mình đặt tên là ``randomkey`` luôn thay đổi và nó luôn là 16 bytes. Tới đây rồi mình đã nghĩ ngay tới đây là một dạng mã hóa kiểu dữ liệu mà đúng hơn nó sẽ là ``AES``. Tuy nhiên nó chỉ là phỏng đoán ban đầu, mình tiếp tục debug, tới hàm ``EXPANDKEY`` sau đó từ 16 bytes random đầu nó thành 176 bytes. Tới đây không nghi ngờ gì nữa đây là khúc expand key trong AES. ( Sau khi có những phỏng đoán mình đã phải dành thời gian làm cryptohack và học về AES nên wu có vẻ sẽ rất trơn trượt nhưng khi làm mình không hề như vậy =))) ) . Lúc này tưởng ngon ăn, mình tưởng bài này anh **Jinn** chắc chỉ cho AES ECB 128 thôi nhỉ?? Chạy thử và so sánh với kết quả encryption trên cyberchef với kết quả chương trình. Oh... 

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/20f15cf7-5c28-4046-96fb-b9dd16d7e714)

Không giống tí nào... Vậy là sao? Nếu mà vậy thì sẽ padding key ở đâu vì nó dùng ``random_chacha`` mà nhỉ? Tới đây thì mình quyết định phải rev vào core của encrypt chứ không thể như này nữa.

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/0912786e-42eb-4e54-8c93-a5be2dcdbf53)

```C
void *__fastcall ENCRYPT(void *a1, char *expand, char *padding)
{
  char *v3; // rax
  unsigned __int64 v4; // rdx
  __int64 v5; // rdx
  __int64 v6; // rax
  __int64 v7; // rdx
  char *v8; // rax
  unsigned __int64 v9; // rdx
  char *v11; // rax
  unsigned __int64 v12; // rdx
  unsigned __int64 v13; // [rsp+8h] [rbp-C0h]
  unsigned __int64 v14; // [rsp+10h] [rbp-B8h]
  char xor_STATE[16]; // [rsp+40h] [rbp-88h] BYREF
  __int64 v16; // [rsp+50h] [rbp-78h]
  __int64 v17; // [rsp+58h] [rbp-70h]
  __int64 v18; // [rsp+60h] [rbp-68h]
  __int64 v19; // [rsp+68h] [rbp-60h]
  __int64 v20[3]; // [rsp+70h] [rbp-58h] BYREF
  __int64 v21; // [rsp+88h] [rbp-40h]
  unsigned __int64 v22; // [rsp+90h] [rbp-38h]
  unsigned __int64 v23; // [rsp+98h] [rbp-30h]
  __int64 v24; // [rsp+A0h] [rbp-28h]
  __int64 v25; // [rsp+A8h] [rbp-20h]
  char *v26; // [rsp+B0h] [rbp-18h]
  char *v27; // [rsp+B8h] [rbp-10h]
  __int64 v28; // [rsp+C0h] [rbp-8h]

  v26 = expand;
  v27 = padding;
  sub_55644CDE3220(xor_STATE, (__int64)padding);
  v16 = 0LL;
  v17 = 4LL;
  v3 = (char *)take_EXPANDKEY();
  addroundkey(xor_STATE, v3, v4);               // xor state with sbox
  v18 = 1LL;
  v19 = 10LL;
  v20[0] = sub_55644CDE3D80(1LL);
  v20[1] = v5;
  while ( 1 )
  {
    v6 = sub_55644CDE3D70(v20);
    v21 = v7;
    v20[2] = v6;
    if ( !v6 )
      break;
    v14 = v21;
    v28 = v21;
    shift_rows(xor_STATE);                      // not that SUS
    mix_column(xor_STATE);                      // last round skip
    if ( !is_mul_ok(4uLL, v14) )
      sub_55644CDE02E0((__int64)"attempt to multiply with overflow", 33LL, (__int64)&off_55644CE6FCE8);
    v13 = 4 * v14;
    if ( !is_mul_ok(4uLL, v14) )
      sub_55644CDE02E0((__int64)"attempt to multiply with overflow", 33LL, (__int64)&off_55644CE6FD00);
    if ( v13 >= 0xFFFFFFFFFFFFFFFCLL )
      sub_55644CDE02E0((__int64)"attempt to add with overflow", 28LL, (__int64)&off_55644CE6FD18);
    v22 = 4 * v14;
    v23 = v13 + 4;
    v11 = (char *)take_EXPANDKEY();             // use subkey
    addroundkey(xor_STATE, v11, v12);
  }
  shift_rows(xor_STATE);
  v24 = 40LL;
  v25 = 44LL;
  v8 = (char *)take_EXPANDKEY();
  addroundkey(xor_STATE, v8, v9);
  sub_55644CDE34B0(a1, xor_STATE);              // AES WITHOUT SUBBYTES
  return a1;
}
```
Sau khi đọc code + debug miệt mài mình khôi phục được như sau vậy là rõ rồi AES ECB without sub bytes. Vậy thì chắc chắn sẽ có cách crack nhỉ. Sau khi research và tất nhiên mình cũng hỏi các anh, các bạn chơi crypto thì mình được những link rất hữu dụng.

> https://medium.com/@wrth/cracking-aes-without-any-one-of-its-operations-c42cdfc0452f
> https://crypto.stackexchange.com/questions/20228/consequences-of-aes-without-any-one-of-its-operations

Vậy nó có thể crack nhưng nhất định phải có một cặp block plain - cipher. Lúc này quay lại vấn đề làm sao để kiếm plain đây? Lúc này mình suy nghĩ là hmm nếu là file png thì nó sẽ có header bytes giống nhau vậy thì lúc này thõa với 16 bytes plaintext rồi. Header bytes: ``89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52``. Final script:

```python
from sage.all import *

def bytes2mat(b):
    a = []
    for i in b:
        tmp = bin(i)[2:].zfill(8)
        for j in tmp:
            a.append(int(j))
    return Matrix(GF(2), a)

def mat2bytes(m):
    a = ""
    for i in range(128):
        a += str(m[0, i])
    a = [a[i:i+8] for i in range(0, 128, 8)]
    a = [int(i, 2) for i in a]
    return bytes(a)

I = identity_matrix(GF(2), 8)
X = Matrix(GF(2), 8, 8)
for i in range(7):
    X[i, i+1] = 1
X[3, 0] = 1
X[4, 0] = 1
X[6, 0] = 1
X[7, 0] = 1

C = block_matrix([
    [X, X+I, I, I],
    [I, X, X+I, I],
    [I, I, X, X+I],
    [X+I, I, I, X]
])

zeros = Matrix(GF(2), 8, 8)
zeros2 = Matrix(GF(2), 32, 32)
o0 = block_matrix([
    [I, zeros, zeros, zeros],
    [zeros, zeros, zeros, zeros],
    [zeros, zeros, zeros, zeros],
    [zeros, zeros, zeros, zeros]
])

o1 = block_matrix([
    [zeros, zeros, zeros, zeros],
    [zeros, I, zeros, zeros],
    [zeros, zeros, zeros, zeros],
    [zeros, zeros, zeros, zeros]
])

o2 = block_matrix([
    [zeros, zeros, zeros, zeros],
    [zeros, zeros, zeros, zeros],
    [zeros, zeros, I, zeros],
    [zeros, zeros, zeros, zeros]
])

o3 = block_matrix([
    [zeros, zeros, zeros, zeros],
    [zeros, zeros, zeros, zeros],
    [zeros, zeros, zeros, zeros],
    [zeros, zeros, zeros, I]
])

S = block_matrix([
    [o0, o1, o2, o3],
    [o3, o0, o1, o2],
    [o2, o3, o0, o1],
    [o1, o2, o3, o0]
])

M = block_matrix([
    [C, zeros2, zeros2, zeros2],
    [zeros2, C, zeros2, zeros2],
    [zeros2, zeros2, C, zeros2],
    [zeros2, zeros2, zeros2, C]
])

R = M*S
A = S*(R**9) # sorry for the inconsistency in the variable name, this is supposed to be SA^9 that I talked about

p = open("censored.png.enc", "rb").read()

p2 = "89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52"

p2 = bytes.fromhex(p2)
ct2 = "2ff89e3a6c9a3747cab74b9300ebcdc8"

ct2 = bytes.fromhex(ct2)
p2 = bytes2mat(p2).transpose()
ct2 = bytes2mat(ct2).transpose()

K = ct2 - A * p2
recovered_plaintext = b""
for i in range(0, len(p), 16):
    block = p[i:i+16]
    block = bytes2mat(block)
    block = (A.inverse() * (block.transpose() - K)).transpose()
    recovered_plaintext += mat2bytes(block)

open("recovered.png", "wb").write(recovered_plaintext)
```

![image](https://github.com/ClownCS/clowncs.github.io/assets/90112096/e396ac0a-9ee8-40ab-8674-888e9d81e390)

Mình sẽ không thể solve nếu không có sự giúp đỡ của các anh, các bạn chơi crypto. Shoud out for crypto players !

> Lời cuối: em xin cảm ơn anh **dream02** và anh **Jinn** vì đã tạo ra những challenge thú vị.


#### References:
* https://redcanary.com/blog/ebpfmon/
* https://www.kernel.org/doc/html/v5.17/bpf/instruction-set.html
* https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
* https://ebpf.io/what-is-ebpf/#jit-compilation
