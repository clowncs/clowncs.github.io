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


> Lời cuối: em xin cảm ơn anh **dream02** và anh **Jinn** vì đã tạo ra những challenge thú vị.


#### References:
* https://redcanary.com/blog/ebpfmon/
* https://www.kernel.org/doc/html/v5.17/bpf/instruction-set.html
* https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
* https://ebpf.io/what-is-ebpf/#jit-compilation
