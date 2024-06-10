---
weight: 1
title: "R3CTF"
date: 2024-06-10
lastmod: 2024-06-10
draft: false
author: "clowncs"
authorLink: "https://clowncs.github.io"
description: "Solutions for some challenges in R3CTF"
tags: ["RE", "Crypto","2024"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---
Solutions for some challenges in R3CTF

<!--more-->

# R3CTF / r3kapig

## TPA 04 - 🔒 / Forensics + Reverse + Crypto

> After the investigation of the previous question, you may have discovered the hacker's intrusion, but it seems that he has launched a ransomware. Some important information of the company has been encrypted. Can you help the company recover it?
> This challenge uses the same attachment as TPA 03 - 💻, and the challenge covers elements of forensics, reverse engineering, and cryptography. You can gather your friends to solve it together
> !!! Note: Please do not run any software extracted from this chal on a physical machine. The organizer is not responsible for any losses caused. !!!
> After investigation, R3 Inc's security department discovered that...pdf, also from the president's office, may have been compromised on the ransomware computer. Colleagues are requested to self-examine their own computer security protection and confidentiality measures. If any abnormality is discovered, please report it to the Security Department in a timely manner.


![image](https://github.com/clowncs/clowncs.github.io/assets/90112096/2cd1f599-3261-45f6-a411-725a1cec7835)


This contest has so damn hard binary challenges so i couldn't solve any of them but the forensics chall that require reverse + crypto so i give it a shot. My foren teammate has dumped for me a exe file (seems the ransomware) and .yr encrypted file. My job begins.

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  CHAR *i; // [rsp+30h] [rbp-4C8h]
  __int64 v5; // [rsp+50h] [rbp-4A8h]
  __int64 v6; // [rsp+60h] [rbp-498h]
  __int64 v7; // [rsp+70h] [rbp-488h]
  __int64 v8; // [rsp+80h] [rbp-478h]
  __int64 v9; // [rsp+A0h] [rbp-458h]
  __int64 v10; // [rsp+B0h] [rbp-448h]
  __int64 v11; // [rsp+C0h] [rbp-438h]
  __int64 v12; // [rsp+C8h] [rbp-430h]
  __int64 v13; // [rsp+D8h] [rbp-420h]
  __int64 v14[5]; // [rsp+E0h] [rbp-418h] BYREF
  __int64 v15[5]; // [rsp+108h] [rbp-3F0h] BYREF
  __int64 v16[5]; // [rsp+130h] [rbp-3C8h] BYREF
  __int64 v17[5]; // [rsp+158h] [rbp-3A0h] BYREF
  __int64 v18[5]; // [rsp+180h] [rbp-378h] BYREF
  __int64 v19[5]; // [rsp+1A8h] [rbp-350h] BYREF
  __int64 v20[5]; // [rsp+1D0h] [rbp-328h] BYREF
  __int64 v21[5]; // [rsp+1F8h] [rbp-300h] BYREF
  DWORD pcbBuffer; // [rsp+220h] [rbp-2D8h] BYREF
  __int64 v23[5]; // [rsp+228h] [rbp-2D0h] BYREF
  __int64 v24[6]; // [rsp+250h] [rbp-2A8h] BYREF
  char v25[272]; // [rsp+280h] [rbp-278h] BYREF
  __int64 v26[8]; // [rsp+390h] [rbp-168h] BYREF
  CHAR Buffer[272]; // [rsp+3D0h] [rbp-128h] BYREF

  antidebug(argc, argv, envp);
  v26[0] = (__int64)"Contacts";
  v26[1] = (__int64)"Desktop";
  v26[2] = (__int64)"Documents";
  v26[3] = (__int64)"Downloads";
  v26[4] = (__int64)"Favorites";
  v26[5] = (__int64)"Music";
  v26[6] = (__int64)"Pictures";
  v26[7] = (__int64)"Videos";
  pcbBuffer = 260;
  if ( !GetUserNameA(Buffer, &pcbBuffer) )
    return 0;
  sub_7FF6EB2CA690(
    (__int64)v24,
    (__int64)"Your files have been encrypted!\n"
             "\n"
             "All your important files, including documents, photos, videos, and databases, have been encrypted using a s"
             "trong encryption algorithm. You will not be able to access your files without the decryption key, which is "
             "known only to us.\n"
             "\n"
             "What happened to my files?\n"
             "Your files have been encrypted to prevent you from accessing them until a ransom is paid. The encryption is"
             " irreversible without our unique decryption software and key.\n"
             "\n"
             "How can I recover my files?\n"
             "To recover your files, you must pay a ransom of 5 Bitcoin (BTC) to the following address:\n"
             "\n"
             "[bc1qldmz3gk6hhhu9mjj4qmpx7gspscml25fxfhj9g]\n"
             "\n"
             "What is Bitcoin?\n"
             "Bitcoin is a form of digital currency. If you are unfamiliar with Bitcoin, please use one of the following "
             "websites to learn how to buy and send Bitcoin:\n"
             "\n"
             "- Coinbase: https://www.coinbase.com\n"
             "- Binance: https://www.binance.com\n"
             "\n"
             "Deadline\n"
             "You have 72 hours to make the payment. If the ransom is not paid within this time frame, the price will dou"
             "ble to 10 BTC. If the ransom is not paid within 7 days, your files will be permanently deleted, and there w"
             "ill be no way to recover them.\n"
             "\n"
             "How do I prove you can decrypt my files?\n"
             "You can send up to 3 encrypted files to us, and we will decrypt them for free to prove we have the decrypti"
             "on key. Send the files to the following email address:\n"
             "\n"
             "[claysfri3nds@proton.me]\n"
             "\n"
             "Important:\n"
             "1. Do not attempt to decrypt the files yourself, as this may cause permanent data loss.\n"
             "2. Do not attempt to contact law enforcement or data recovery services, as this will not help you recover y"
             "our files and may result in the permanent loss of your data.\n"
             "\n"
             "What to do next?\n"
             "1. Purchase the required amount of Bitcoin.\n"
             "2. Send the Bitcoin to the provided address.\n"
             "3. Email us at [bbb@hacker.com] with your transaction ID and a few sample files.\n"
             "4. Receive the decryption key and software to recover your files.\n"
             "\n"
             "We are monitoring your actions and communications to ensure compliance with our demands. Non-compliance wil"
             "l result in the permanent loss of your files.\n"
             "\n"
             "Contact Us\n"
             "For any questions or issues, please contact us at:\n"
             "\n"
             "[contact@hacker.com]\n"
             "\n"
             "Your personal ID: [327A6C4304AD5938EAF0EFB6CC3E53DC]\n"
             "\n"
             "Remember, the only way to recover your files is by paying the ransom. Any attempts to restore your data wit"
             "hout our assistance will lead to irreversible data loss.\n");
  memsEX(v25, 0x108ui64);
  v5 = sub_7FF6EB2CA690((__int64)v17, (__int64)Buffer);
  v6 = sub_7FF6EB2CEF30(v16, "C:\\Users\\", v5);
  v7 = sub_7FF6EB2CEEA0((__int64)v15, v6, (__int64)"\\");
  v8 = sub_7FF6EB2CEEA0((__int64)v14, v7, (__int64)"!!!!ransom_note!!!!.txt");
  sub_7FF6EB2C7650((__int64)v25, v8, 2, 64, 1);
  sub_7FF6EB2CA570(v14);
  sub_7FF6EB2CA570(v15);
  sub_7FF6EB2CA570(v16);
  sub_7FF6EB2CA570(v17);
  if ( (unsigned __int8)sub_7FF6EB2C75A0(v25) )
  {
    sub_7FF6EB2CEF80(v25, v24);
    sub_7FF6EB2C7540(v25);
  }
  for ( i = (CHAR *)v26; i != Buffer; i += 8 )
  {
    v11 = *(_QWORD *)i;
    v9 = sub_7FF6EB2CA690((__int64)v21, (__int64)Buffer);
    v10 = sub_7FF6EB2CEF30(v20, "C:\\Users\\", v9);
    v12 = sub_7FF6EB2CEEA0((__int64)v19, v10, (__int64)"\\");
    v13 = sub_7FF6EB2CEEA0((__int64)v18, v12, v11);
    sub_7FF6EB2CEEA0((__int64)v23, v13, (__int64)"\\*");
    sub_7FF6EB2CA570(v18);
    sub_7FF6EB2CA570(v19);
    sub_7FF6EB2CA570(v20);
    sub_7FF6EB2CA570(v21);
    seem_enc((__int64)v23);
    sub_7FF6EB2CA570(v23);
  }
  sub_7FF6EB2C6A30((__int64)v25);
  sub_7FF6EB2CA570(v24);
  return 0;
}
```

This is the main function. First is the anti debug function, this is easy to bypass by patch the condition. Next it will get user name and then write the ``!!!!ransom_note!!!!.txt`` to ``C:\Users\<username>``.

```C
 for ( i = (CHAR *)v26; i != Buffer; i += 8 )
  {
    v11 = *(_QWORD *)i;
    v9 = sub_7FF6EB2CA690((__int64)v21, (__int64)Buffer);
    v10 = sub_7FF6EB2CEF30(v20, "C:\\Users\\", v9);
    v12 = sub_7FF6EB2CEEA0((__int64)v19, v10, (__int64)"\\");
    v13 = sub_7FF6EB2CEEA0((__int64)v18, v12, v11);
    sub_7FF6EB2CEEA0((__int64)v23, v13, (__int64)"\\*");
    sub_7FF6EB2CA570(v18);
    sub_7FF6EB2CA570(v19);
    sub_7FF6EB2CA570(v20);
    sub_7FF6EB2CA570(v21);
    seem_enc((__int64)v23);
    sub_7FF6EB2CA570(v23);
  }
```

Next step this will load all the folder with order of v26 ( Contact, Desktop, ... ) and encrypt it. Lets dig down about ``seem_enc`` func.

```C
int __fastcall seem_enc(__int64 folde)
{
  const CHAR *v1; // rax
  HANDLE FirstFileA; // rax
  __int64 v3; // rdx
  __int64 v4; // rdx
  __int64 v5; // rdx
  int v6; // eax
  bool v8; // [rsp+30h] [rbp-498h]
  __int64 v9; // [rsp+38h] [rbp-490h]
  HANDLE hFindFile; // [rsp+40h] [rbp-488h]
  int v11; // [rsp+48h] [rbp-480h]
  __int64 v12; // [rsp+80h] [rbp-448h]
  __int64 v13; // [rsp+88h] [rbp-440h]
  __int64 v14; // [rsp+90h] [rbp-438h]
  __int64 v15; // [rsp+B8h] [rbp-410h]
  __int64 v16; // [rsp+C0h] [rbp-408h]
  __int64 v17; // [rsp+D8h] [rbp-3F0h]
  __int64 v18; // [rsp+E0h] [rbp-3E8h]
  __int64 v19; // [rsp+F0h] [rbp-3D8h]
  __int64 v20; // [rsp+100h] [rbp-3C8h]
  __int64 v21; // [rsp+110h] [rbp-3B8h]
  char v22[24]; // [rsp+118h] [rbp-3B0h] BYREF
  char v23[24]; // [rsp+130h] [rbp-398h] BYREF
  char v24[24]; // [rsp+148h] [rbp-380h] BYREF
  __int64 v25[5]; // [rsp+160h] [rbp-368h] BYREF
  __int64 v26[5]; // [rsp+188h] [rbp-340h] BYREF
  __int64 v27[5]; // [rsp+1B0h] [rbp-318h] BYREF
  char v28[24]; // [rsp+1D8h] [rbp-2F0h] BYREF
  char v29[24]; // [rsp+1F0h] [rbp-2D8h] BYREF
  char v30[24]; // [rsp+208h] [rbp-2C0h] BYREF
  char v31[24]; // [rsp+220h] [rbp-2A8h] BYREF
  char v32[24]; // [rsp+238h] [rbp-290h] BYREF
  __int64 v33[5]; // [rsp+250h] [rbp-278h] BYREF
  __int64 v34[5]; // [rsp+278h] [rbp-250h] BYREF
  __int64 v35[5]; // [rsp+2A0h] [rbp-228h] BYREF
  __int64 v36[5]; // [rsp+2C8h] [rbp-200h] BYREF
  __int64 v37[5]; // [rsp+2F0h] [rbp-1D8h] BYREF
  __int64 v38[5]; // [rsp+318h] [rbp-1B0h] BYREF
  __int64 v39[6]; // [rsp+340h] [rbp-188h] BYREF
  struct _WIN32_FIND_DATAA FindFileData; // [rsp+370h] [rbp-158h] BYREF

  v1 = (const CHAR *)sub_7FF6EB2CA3F0(folde);
  FirstFileA = FindFirstFileA(v1, &FindFileData);
  hFindFile = FirstFileA;
  if ( FirstFileA != (HANDLE)-1i64 )
  {
    do
    {
      sub_7FF6EB2CA690((__int64)v35, (__int64)FindFileData.cFileName);
      if ( (FindFileData.dwFileAttributes & 0x10) != 0 )
      {
        if ( sub_7FF6EB2CEEF0((__int64)v35, (__int64)".") && sub_7FF6EB2CEEF0((__int64)v35, (__int64)"..") )
        {
          v6 = unknown_libname_120(folde);
          v20 = sub_7FF6EB2CA2F0(folde, (__int64)v27, 0, v6 - 1);
          v21 = sub_7FF6EB2CEE50(v26, v20, v35);
          sub_7FF6EB2CEEA0((__int64)v39, v21, (__int64)"\\*");
          sub_7FF6EB2CA570(v26);
          sub_7FF6EB2CA570(v27);
          seem_enc((__int64)v39);
          sub_7FF6EB2CA570(v39);
        }
      }
      else
      {
        sub_7FF6EB2CA690((__int64)v34, (__int64)FindFileData.cFileName);
        LOBYTE(v3) = 46;
        v9 = sub_7FF6EB2CA350(v34, v3, -1i64);
        if ( v9 != -1 && v9 )
        {
          sub_7FF6EB2CA2F0((int)v34, (__int64)v33, v9, -1);
          v12 = sub_7FF6EB2CA480((__int64)v33, (__int64)v28);
          v13 = std::string::end(v33, v29);
          v14 = sub_7FF6EB2CA480((__int64)v33, (__int64)v30);
          sub_7FF6EB2CEA40((__int64)v22, v14, v13, v12, (__int64 (__fastcall *)(_QWORD))tolower);
          sub_7FF6EB2C64F0((__int64)v22);
          v15 = sub_7FF6EB2C8E80((__int64)&unk_7FF6EB3560E8, (__int64)v31);
          v16 = sub_7FF6EB2C8EE0((__int64)&unk_7FF6EB3560E8, (__int64)v32);
          v18 = sub_7FF6EB2CEC90((__int64)v24, v16, v15, (__int64)v33);
          v17 = sub_7FF6EB2C8E80((__int64)&unk_7FF6EB3560E8, (__int64)v23);
          v8 = sub_7FF6EB2C7450(v18, v17);
          sub_7FF6EB2C64F0((__int64)v23);
          sub_7FF6EB2C64F0((__int64)v24);
          if ( v8 )
          {
            LOBYTE(v4) = 42;
            if ( sub_7FF6EB2CA350(folde, v4, -1i64) == -1 )
            {
              v11 = unknown_libname_120(folde);
            }
            else
            {
              LOBYTE(v5) = '*';
              v11 = sub_7FF6EB2CA350(folde, v5, -1i64);
            }
            sub_7FF6EB2CA2F0(folde, (__int64)v37, 0, v11);
            sub_7FF6EB2CED60((__int64)v36, (__int64)v37, (__int64)v34);
            v19 = sub_7FF6EB2CED60((__int64)v25, (__int64)v37, (__int64)v34);
            createnewfile((__int64)v38, v19, (__int64)".yr");
            sub_7FF6EB2CA570(v25);
            coreee((__int64)v36, (__int64)v38);
            sub_7FF6EB2CA3F0((__int64)v36);
            sub_7FF6EB2CA570(v38);
            sub_7FF6EB2CA570(v36);
            sub_7FF6EB2CA570(v37);
          }
          sub_7FF6EB2CA570(v33);
        }
        sub_7FF6EB2CA570(v34);
      }
      sub_7FF6EB2CA570(v35);
    }
    while ( FindNextFileA(hFindFile, &FindFileData) );
    LODWORD(FirstFileA) = FindClose(hFindFile);
  }
  return (int)FirstFileA;
}
```

The original one contains ``DeleteFile`` this will delete our original files but when i analyze it just be careful so i patched this out.

```C
    sub_14000A2F0(a1, v38, 0i64, v12);
    sub_14000ED60(v37, v38, v35);
    v20 = sub_14000ED60(v26, v38, v35);
    sub_14000EEA0(v39, v20, ".yr");
    sub_14000A570(v26);
    sub_140006790(v37, v39);
    v6 = (const CHAR *)sub_14000A3F0(v37);
    DeleteFileA(v6);
    sub_14000A570(v39);
    sub_14000A570(v37);
    sub_14000A570(v38);
```

So it will load each file in the folder name, and then goto ``core`` function. This is actually encryption. 

```C
__int64 __fastcall coreee(__int64 a1, __int64 a2)
{
  char v3[8]; // [rsp+30h] [rbp-328h] BYREF
  __int64 v4; // [rsp+38h] [rbp-320h]
  __int64 v5; // [rsp+40h] [rbp-318h]
  __int64 v6; // [rsp+48h] [rbp-310h]
  char v7[16]; // [rsp+50h] [rbp-308h] BYREF
  char v8[16]; // [rsp+60h] [rbp-2F8h] BYREF
  char v9[16]; // [rsp+70h] [rbp-2E8h] BYREF
  char v10[16]; // [rsp+80h] [rbp-2D8h] BYREF
  char v11[16]; // [rsp+90h] [rbp-2C8h] BYREF
  char v12[16]; // [rsp+A0h] [rbp-2B8h] BYREF
  char v13[16]; // [rsp+B0h] [rbp-2A8h] BYREF
  char v14[16]; // [rsp+C0h] [rbp-298h] BYREF
  _QWORD v15[4]; // [rsp+D0h] [rbp-288h] BYREF
  __int64 v16[4]; // [rsp+F0h] [rbp-268h] BYREF
  char v17[272]; // [rsp+110h] [rbp-248h] BYREF
  char v18[272]; // [rsp+220h] [rbp-138h] BYREF

  memsEX(v18, 0x110ui64);
  sub_7FF6EB2C8D40((__int64)v18, a1, 32, 0x40u, 1);
  memsEX(v17, 0x108ui64);
  sub_7FF6EB2C7650((__int64)v17, a2, 32, 64, 1);
  memsEX(v16, 0x20ui64);
  v4 = unknown_libname_119((__int64)v3);
  qmemcpy(v7, (const void *)sub_7FF6EB2C7510(v13), sizeof(v7));
  qmemcpy(v9, v7, sizeof(v9));
  qmemcpy(v8, (const void *)sub_7FF6EB2C7490((__int64)v14, (__int64)v18), sizeof(v8));
  qmemcpy(v10, v8, sizeof(v10));
  qmemcpy(v11, v9, sizeof(v11));
  qmemcpy(v12, v10, sizeof(v12));
  sub_7FF6EB2CE880(v16, v12, (const struct __crt_win32_buffer_empty_debug_info *)v11, v4);
  memsEX(v15, 32ui64);
  AES(v15, (__int64)v16, (__int64)&iv, (__int64)key);
  v5 = sub_7FF6EB2C9550((__int64)v15);
  v6 = sub_7FF6EB2C9580((__int64)v15);
  sub_7FF6EB2C76E0((__int64)v17, v6, v5);
  sub_7FF6EB2C9B90(v15);
  sub_7FF6EB2C9B90(v16);
  writetonewfile((__int64)v17);
  return sub_7FF6EB2C69F0((__int64)v18);
}
```

As you can see this one will use AES to encrypt our files but it is not standard one. The ``iv`` and ``key`` value is actually generate by random function.

```C
__int64 __fastcall gen_key_iv(__int64 a1, __int64 a2)
{
  _BYTE *v3; // [rsp+20h] [rbp-18h]
  __int64 v4; // [rsp+28h] [rbp-10h]

  sub_7FF6EB2D2110(a1, a2);
  v3 = (_BYTE *)sub_7FF6EB2CE5A0(a1);
  v4 = sub_7FF6EB2CE5A0(a2);
  while ( v3 != (_BYTE *)v4 )
    *v3++ = (rand() % 256);;
  sub_7FF6EB2C64F0(a1);
  return sub_7FF6EB2C64F0(a2);
}
```

And one more sussy thing. In ``initterm((_PVFV *)&First, (_PVFV *)&Last);``, there is one function that initial the SBOX array.

```C
int SBOX_init()
{
  char v1[16]; // [rsp+20h] [rbp-478h] BYREF
  int v2[256]; // [rsp+30h] [rbp-468h] BYREF
  char v3[16]; // [rsp+430h] [rbp-68h] BYREF
  __int64 v4; // [rsp+440h] [rbp-58h]
  char v5[16]; // [rsp+448h] [rbp-50h] BYREF
  char v6[16]; // [rsp+460h] [rbp-38h] BYREF
  char v7[40]; // [rsp+470h] [rbp-28h] BYREF

  memsEX(sbox, 0x20ui64);
  v4 = unknown_libname_119((__int64)v1);
  v2[0] = 131;
  v2[1] = 246;
  v2[2] = 208;
  v2[3] = 165;
  v2[4] = 110;
  v2[5] = 27;
  v2[6] = 61;
  v2[7] = 72;
  v2[8] = 21;
  v2[9] = 96;
  v2[10] = 70;
  v2[11] = 51;
  v2[12] = 248;
  v2[13] = 141;
  v2[14] = 171;
  v2[15] = 222;
  v2[16] = 189;
  v2[17] = 200;
  v2[18] = 238;
  v2[19] = 155;
  v2[20] = 80;
  v2[21] = 37;
  v2[22] = 3;
  v2[23] = 118;
  v2[24] = 43;
  v2[25] = 94;
  v2[26] = 120;
  v2[27] = 13;
  v2[28] = 198;
  v2[29] = 179;
  v2[30] = 149;
  v2[31] = 224;
  v2[32] = 45;
  v2[33] = 88;
  v2[34] = 126;
  v2[35] = 11;
  v2[36] = 192;
  v2[37] = 181;
  v2[38] = 147;
  v2[39] = 230;
  v2[40] = 187;
  v2[41] = 206;
  v2[42] = 232;
  v2[43] = 157;
  v2[44] = 86;
  v2[45] = 35;
  v2[46] = 5;
  v2[47] = 112;
  v2[48] = 19;
  v2[49] = 102;
  v2[50] = 64;
  v2[51] = 53;
  v2[52] = 254;
  v2[53] = 139;
  v2[54] = 173;
  v2[55] = 216;
  v2[56] = 133;
  v2[57] = 240;
  v2[58] = 214;
  v2[59] = 163;
  v2[60] = 104;
  v2[61] = 29;
  v2[62] = 59;
  v2[63] = 78;
  v2[64] = 7;
  v2[65] = 114;
  v2[66] = 84;
  v2[67] = 33;
  v2[68] = 234;
  v2[69] = 159;
  v2[70] = 185;
  v2[71] = 204;
  v2[72] = 145;
  v2[73] = 228;
  v2[74] = 194;
  v2[75] = 183;
  v2[76] = 124;
  v2[77] = 9;
  v2[78] = 47;
  v2[79] = 90;
  v2[80] = 57;
  v2[81] = 76;
  v2[82] = 106;
  v2[83] = 31;
  v2[84] = 212;
  v2[85] = 161;
  v2[86] = 135;
  v2[87] = 242;
  v2[88] = 175;
  v2[89] = 218;
  v2[90] = 252;
  v2[91] = 137;
  v2[92] = 66;
  v2[93] = 55;
  v2[94] = 17;
  v2[95] = 100;
  v2[96] = 169;
  v2[97] = 220;
  v2[98] = 250;
  v2[99] = 143;
  v2[100] = 68;
  v2[101] = 49;
  v2[102] = 23;
  v2[103] = 98;
  v2[104] = 63;
  v2[105] = 74;
  v2[106] = 108;
  v2[107] = 25;
  v2[108] = 210;
  v2[109] = 167;
  v2[110] = 129;
  v2[111] = 244;
  v2[112] = 151;
  v2[113] = 226;
  v2[114] = 196;
  v2[115] = 177;
  v2[116] = 122;
  v2[117] = 15;
  v2[118] = 41;
  v2[119] = 92;
  v2[120] = 1;
  v2[121] = 116;
  v2[122] = 82;
  v2[123] = 39;
  v2[124] = 236;
  v2[125] = 153;
  v2[126] = 191;
  v2[127] = 202;
  v2[128] = 38;
  v2[129] = 83;
  v2[130] = 117;
  v2[131] = 0;
  v2[132] = 203;
  v2[133] = 190;
  v2[134] = 152;
  v2[135] = 237;
  v2[136] = 176;
  v2[137] = 197;
  v2[138] = 227;
  v2[139] = 150;
  v2[140] = 93;
  v2[141] = 40;
  v2[142] = 14;
  v2[143] = 123;
  v2[144] = 24;
  v2[145] = 109;
  v2[146] = 75;
  v2[147] = 62;
  v2[148] = 245;
  v2[149] = 128;
  v2[150] = 166;
  v2[151] = 211;
  v2[152] = 142;
  v2[153] = 251;
  v2[154] = 221;
  v2[155] = 168;
  v2[156] = 99;
  v2[157] = 22;
  v2[158] = 48;
  v2[159] = 69;
  v2[160] = 136;
  v2[161] = 253;
  v2[162] = 219;
  v2[163] = 174;
  v2[164] = 101;
  v2[165] = 16;
  v2[166] = 54;
  v2[167] = 67;
  v2[168] = 30;
  v2[169] = 107;
  v2[170] = 77;
  v2[171] = 56;
  v2[172] = 243;
  v2[173] = 134;
  v2[174] = 160;
  v2[175] = 213;
  v2[176] = 182;
  v2[177] = 195;
  v2[178] = 229;
  v2[179] = 144;
  v2[180] = 91;
  v2[181] = 46;
  v2[182] = 8;
  v2[183] = 125;
  v2[184] = 32;
  v2[185] = 85;
  v2[186] = 115;
  v2[187] = 6;
  v2[188] = 205;
  v2[189] = 184;
  v2[190] = 158;
  v2[191] = 235;
  v2[192] = 162;
  v2[193] = 215;
  v2[194] = 241;
  v2[195] = 132;
  v2[196] = 79;
  v2[197] = 58;
  v2[198] = 28;
  v2[199] = 105;
  v2[200] = 52;
  v2[201] = 65;
  v2[202] = 103;
  v2[203] = 18;
  v2[204] = 217;
  v2[205] = 172;
  v2[206] = 138;
  v2[207] = 255;
  v2[208] = 156;
  v2[209] = 233;
  v2[210] = 207;
  v2[211] = 186;
  v2[212] = 113;
  v2[213] = 4;
  v2[214] = 34;
  v2[215] = 87;
  v2[216] = 10;
  v2[217] = 127;
  v2[218] = 89;
  v2[219] = 44;
  v2[220] = 231;
  v2[221] = 146;
  v2[222] = 180;
  v2[223] = 193;
  v2[224] = 12;
  v2[225] = 121;
  v2[226] = 95;
  v2[227] = 42;
  v2[228] = 225;
  v2[229] = 148;
  v2[230] = 178;
  v2[231] = 199;
  v2[232] = 154;
  v2[233] = 239;
  v2[234] = 201;
  v2[235] = 188;
  v2[236] = 119;
  v2[237] = 2;
  v2[238] = 36;
  v2[239] = 81;
  v2[240] = 50;
  v2[241] = 71;
  v2[242] = 97;
  v2[243] = 20;
  v2[244] = 223;
  v2[245] = 170;
  v2[246] = 140;
  v2[247] = 249;
  v2[248] = 164;
  v2[249] = 209;
  v2[250] = 247;
  v2[251] = 130;
  v2[252] = 73;
  v2[253] = 60;
  v2[254] = 26;
  v2[255] = 111;
  qmemcpy(
    v5,
    (const void *)std::u16string_view::basic_string_view<char16_t,std::char_traits<char16_t>>(v7, v2, v3),
    sizeof(v5));
  qmemcpy(v6, v5, sizeof(v6));
  sub_7FF6EB2CA0A0(sbox, (__FrameHandler3::TryBlockMap *)v6);
  return atexit(sub_7FF6EB332330);
}
```

But as you can see, this is not standard SBOX. So at this time i thought this is AES with bad SBOX. But when i ask my cryptomate to try to decrypt it, he said something is weird? So i go to debug and read each step again. This is a core function of encrypt.

```C
_QWORD *__fastcall coree(__int64 a1, _QWORD *a2, __int64 a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  int i; // [rsp+20h] [rbp-158h]
  void *v7; // [rsp+28h] [rbp-150h]
  void *v8; // [rsp+30h] [rbp-148h]
  void *v9; // [rsp+38h] [rbp-140h]
  void *v10; // [rsp+40h] [rbp-138h]
  void *v11; // [rsp+48h] [rbp-130h]
  void *v12; // [rsp+50h] [rbp-128h]
  void *v13; // [rsp+58h] [rbp-120h]
  __int64 v14[4]; // [rsp+68h] [rbp-110h] BYREF
  __int64 v15[4]; // [rsp+88h] [rbp-F0h] BYREF
  __int64 v16[4]; // [rsp+A8h] [rbp-D0h] BYREF
  __int64 v17[4]; // [rsp+C8h] [rbp-B0h] BYREF
  __int64 v18[4]; // [rsp+E8h] [rbp-90h] BYREF
  __int64 v19[4]; // [rsp+108h] [rbp-70h] BYREF
  __int64 v20[4]; // [rsp+128h] [rbp-50h] BYREF
  char v21[32]; // [rsp+148h] [rbp-30h] BYREF

  memsEX(v21, 0x20ui64);
  expand_keyyy(a1, v21, a1);
  memsEX(a2, 0x20ui64);
  sub_7FF6EB2C9DF0(a2, a3);
  for ( i = 0; i < 10; ++i )
  {
    v7 = subbytes(a1, v14, (__int64)a2);
    sub_7FF6EB2C9C10(a2, (__int64)v7);
    sub_7FF6EB2C9B90(v14);
    v8 = shift_row(a1, v15, (__int64)a2);
    sub_7FF6EB2C9C10(a2, (__int64)v8);
    sub_7FF6EB2C9B90(v15);
    v9 = mix_column(a1, v16, (__int64)a2);
    sub_7FF6EB2C9C10(a2, (__int64)v9);
    sub_7FF6EB2C9B90(v16);
    v3 = sub_7FF6EB2C91C0((__int64)v21, i);
    v10 = xor_round_key(a1, v17, (__int64)a2, v3);
    sub_7FF6EB2C9C10(a2, (__int64)v10);
    sub_7FF6EB2C9B90(v17);
  }
  v11 = subbytes(a1, v18, (__int64)a2);
  sub_7FF6EB2C9C10(a2, (__int64)v11);
  sub_7FF6EB2C9B90(v18);
  v12 = shift_row(a1, v19, (__int64)a2);
  sub_7FF6EB2C9C10(a2, (__int64)v12);
  sub_7FF6EB2C9B90(v19);
  v4 = sub_7FF6EB2C9100((__int64)v21);
  v13 = xor_round_key(a1, v20, (__int64)a2, v4);
  sub_7FF6EB2C9C10(a2, (__int64)v13);
  sub_7FF6EB2C9B90(v20);
  sub_7FF6EB2C92C0(v21);
  return a2;
}
```

When i debugged and examined with each step, i recognize the key expanse seems not correct so i decided to open a ticket and asked author. 

![image](https://github.com/clowncs/clowncs.github.io/assets/90112096/85d25629-fae2-4bc7-b7fe-8b3a3509527b)

That's the key expanse seems not standard, i tried to understand what the hell it did but it was 4 a.m in my country so i was really tired... After the contest i decided to ask author what did he actually do and i got this.

```C
vector<vector<uint8_t>> gen_round_keys(const vector<uint8_t> &key)
{
    vector<vector<uint8_t>> roundkeys = {key};
    for (int i = 0; i < ROUNDS; ++i)
        roundkeys.push_back(shift_rows(sub_bytes(roundkeys.back())));
    return roundkeys;
}
```

Now it is clear, the standard one is ``shift_row`` then go through ``subbytes`` and finally xor with ``rcons``. So basically if we understand the key expand step, we can regenerate the key round and decrypt it by knowing 32 bytes plaintext and 32 bytes encrypted. The POC i take from author and it works LOL.

```python
# This is basicly the AES in sy5tem.exe
# gen_round_keys part is not standard AES

BLOCK_SIZE = 16
ROUNDS = 10

MIX_C = [[0x2, 0x3, 0x1, 0x1], [0x1, 0x2, 0x3, 0x1],
         [0x1, 0x1, 0x2, 0x3], [0x3, 0x1, 0x1, 0x2]]
MIX_C_INV = [[0xe, 0xb, 0xd, 0x9], [0x9, 0xe, 0xb, 0xd],
             [0xd, 0x9, 0xe, 0xb], [0xb, 0xd, 0x9, 0xe]]

SHIFT_ROWS = [[0, 5, 10, 15], [4, 9, 14, 3], [8, 13, 2, 7], [12, 1, 6, 11]]
SHIFT_ROWS_INV = [[0, 13, 10, 7], [4, 1, 14, 11], [8, 5, 2, 15], [12, 9, 6, 3]]

class AES:
    def __init__(self, key: bytes, iv: bytes, sbox, inv_sbox):
        assert len(key) == BLOCK_SIZE and len(iv) == BLOCK_SIZE

        self.key, self.iv = key, iv
        self.sbox = sbox
        self.inv_sbox = inv_sbox

    def sub_bytes(self, block: bytes, inv: bool = False) -> bytes:
        box = self.sbox if not inv else self.inv_sbox

        return bytes([box[i] for i in block])

    def mix_columns(self, block: bytes, inv: bool = False) -> bytes:
        mix = MIX_C_INV if inv else MIX_C

        def mul(x: int, i: int) -> int:
            ans, res = 0, x
            while i:
                if i & 1:
                    ans = ans ^ res
                res <<= 1
                if res & 0x100:
                    res ^= 0b100011011
                i >>= 1
            return ans

        def xor(a: int, b: int, c: int, d: int) -> int:
            return a ^ b ^ c ^ d

        return bytes(sum([[
            xor(*[mul(block[i + j], mix[k][j]) for j in range(4)]) for k in range(4)
        ] for i in range(0, 16, 4)], []))

    def shift_rows(self, block, inv: bool = False):
        shift = SHIFT_ROWS_INV if inv else SHIFT_ROWS

        return bytes([block[shift[i][j]] for i in range(4) for j in range(4)])

    def gen_round_keys(self, key):
        roundkeys = [key]
        for _ in range(ROUNDS):
            roundkeys += [self.shift_rows(self.sub_bytes(roundkeys[-1]))]
        return roundkeys

    def xor_round_key(self, block, roundkey):
        return bytes([block[i] ^ roundkey[i] for i in range(BLOCK_SIZE)])

    def pad(self, plaintext: bytes) -> bytes:
        length = BLOCK_SIZE - len(plaintext) % BLOCK_SIZE
        return plaintext + bytes([length] * length)

    def unpad(self, plaintext: bytes) -> bytes:
        if all([plaintext[-1] == i for i in plaintext[-plaintext[-1]:]]):
            return plaintext[:-plaintext[-1]]
        return plaintext

    def block_encrypt(self, block: bytes) -> bytes:
        roundkeys = self.gen_round_keys(self.key)
        for i in range(ROUNDS):
            block = self.sub_bytes(block)
            block = self.shift_rows(block)
            block = self.mix_columns(block)
            block = self.xor_round_key(block, roundkeys[i])
        block = self.sub_bytes(block)
        block = self.shift_rows(block)
        block = self.xor_round_key(block, roundkeys[-1])
        return block

    def block_decrypt(self, block: bytes) -> bytes:
        roundkeys = self.gen_round_keys(self.key)
        block = self.xor_round_key(block, roundkeys[-1])
        block = self.shift_rows(block, inv=True)
        block = self.sub_bytes(block, inv=True)
        for i in range(ROUNDS-1, -1, -1):
            block = self.xor_round_key(block, roundkeys[i])
            block = self.mix_columns(block, inv=True)
            block = self.shift_rows(block, inv=True)
            block = self.sub_bytes(block, inv=True)
        return block

    def encrypt(self, plaintext: bytes) -> bytes:
        plaintext = self.pad(plaintext)
        blocks = [plaintext[i:i + BLOCK_SIZE]
                  for i in range(0, len(plaintext), BLOCK_SIZE)]
        ciphertext = b''
        mask = self.iv
        for block in blocks:
            res = [block[i] ^ mask[i] for i in range(BLOCK_SIZE)]
            res = self.block_encrypt(res)
            ciphertext += res
            mask = res
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        blocks = [ciphertext[i:i + BLOCK_SIZE]
                  for i in range(0, len(ciphertext), BLOCK_SIZE)]
        plaintext = b''
        mask = self.iv
        for block in blocks:
            decrypted_block = self.block_decrypt(block)
            res = bytes([decrypted_block[i] ^ mask[i]
                        for i in range(BLOCK_SIZE)])
            plaintext += res
            mask = block
        return plaintext


if __name__ == '__main__':
    from special import sbox as s_sbox
    s_box_inv = {v: k for k, v in enumerate(s_sbox)}

    key = iv = b'\x00'*BLOCK_SIZE
    cbc = AES(key, iv, sbox=s_sbox, inv_sbox=s_box_inv)
    plaintext = b'Hello, World!'
    ciphertext = cbc.encrypt(plaintext)
    print(" ".join(map(str, list(ciphertext))))
    print(cbc.decrypt(ciphertext))
```
```python
# This is the S-Box using in sy5tem.exe
# and it's linear
sbox = [131, 246, 208, 165, 110, 27, 61, 72, 21, 96, 70, 51, 248, 141, 171, 222, 189, 200, 238, 155, 80, 37, 3, 118, 43, 94, 120, 13, 198, 179, 149, 224, 45, 88, 126, 11, 192, 181, 147, 230, 187, 206, 232, 157, 86, 35, 5, 112, 19, 102, 64, 53, 254, 139, 173, 216, 133, 240, 214, 163, 104, 29, 59, 78, 7, 114, 84, 33, 234, 159, 185, 204, 145, 228, 194, 183, 124, 9, 47, 90, 57, 76, 106, 31, 212, 161, 135, 242, 175, 218, 252, 137, 66, 55, 17, 100, 169, 220, 250, 143, 68, 49, 23, 98, 63, 74, 108, 25, 210, 167, 129, 244, 151, 226, 196, 177, 122, 15, 41, 92, 1, 116, 82, 39, 236, 153, 191, 202, 38, 83, 117, 0, 203, 190, 152, 237, 176, 197, 227, 150, 93, 40, 14, 123, 24, 109, 75, 62, 245, 128, 166, 211, 142, 251, 221, 168, 99, 22, 48, 69, 136, 253, 219, 174, 101, 16, 54, 67, 30, 107, 77, 56, 243, 134, 160, 213, 182, 195, 229, 144, 91, 46, 8, 125, 32, 85, 115, 6, 205, 184, 158, 235, 162, 215, 241, 132, 79, 58, 28, 105, 52, 65, 103, 18, 217, 172, 138, 255, 156, 233, 207, 186, 113, 4, 34, 87, 10, 127, 89, 44, 231, 146, 180, 193, 12, 121, 95, 42, 225, 148, 178, 199, 154, 239, 201, 188, 119, 2, 36, 81, 50, 71, 97, 20, 223, 170, 140, 249, 164, 209, 247, 130, 73, 60, 26, 111]
```

```python
from utils import AES
import numpy as np

from special import sbox as s_sbox

def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

def difference_distribution_table(sbox):
    box_size = len(sbox)
    table = np.zeros((box_size, box_size), dtype=int)
    for input_diff in range(box_size):
        for x_1 in range(box_size):
            x_2 = x_1 ^ input_diff
            out_diff = s_sbox[x_1] ^ s_sbox[x_2]
            table[input_diff, out_diff] += 1
    return table

t = difference_distribution_table(s_sbox)
sbox_diff_dic = {}
inv_sbox_diff_dic = {}

for i in range(256):
    for j in range(256):
        if t[i, j] == 256:
            sbox_diff_dic.setdefault(i, j)
            inv_sbox_diff_dic.setdefault(j, i)

to_be_decrypt = open('jne.png.yr', 'rb').read()

some_plaintext = open('haha.png', 'rb').read()[:32]
encrypted_plaintext = to_be_decrypt[:32]

cipher = AES(key=b'\x00'*16, iv=b'\x00'*16,
             sbox=sbox_diff_dic, inv_sbox=inv_sbox_diff_dic)

assert len(some_plaintext) == 32 and len(encrypted_plaintext) >= 32 and len(to_be_decrypt) >= 16

D = cipher.decrypt(xor(encrypted_plaintext[:16], to_be_decrypt[:16]))
plaintext = xor(some_plaintext[:16], D)

from tqdm import tqdm

for i in tqdm(range(len(to_be_decrypt) // 16 - 1)):
    d = xor(encrypted_plaintext[:16], to_be_decrypt[i*16:(i+1)*16])
    D = cipher.decrypt(xor(encrypted_plaintext[16:32], to_be_decrypt[(i+1)*16:(i+2)*16]))
    plaintext += xor(xor(some_plaintext[16:32], D), d)

open('jne.png', 'wb').write(cipher.unpad(plaintext))
```

![image](https://github.com/clowncs/clowncs.github.io/assets/90112096/f18e3528-392e-49b6-88a4-26fc77497836)

This challenge is really fun XD.







