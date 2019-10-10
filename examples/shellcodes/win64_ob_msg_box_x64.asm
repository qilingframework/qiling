cld    
and    rsp,0xfffffffffffffff0
call   fuc1
push   r9
push   r8
push   rdx
push   rcx
push   rsi
xor    rdx,rdx
mov    rdx,QWORD PTR gs:[rdx+0x60]
mov    rdx,QWORD PTR ds:[rdx+0x18]
mov    rdx,QWORD PTR ds:[rdx+0x20]
jmp6:
mov    rsi,QWORD PTR ds:[rdx+0x50]
movzx  rcx,WORD PTR ds:[rdx+0x4a]
xor    r9,r9
loop1 :
xor    rax,rax
lods   al,BYTE PTR ds:[rsi]
cmp    al,0x61
jl     jmp1
sub    al,0x20
jmp1 : 
ror    r9d,0xd
add    r9d,eax
loop   loop1
push   rdx
push   r9
mov    rdx,QWORD PTR ds:[rdx+0x20]
mov    eax,DWORD PTR ds:[rdx+0x3c]
add    rax,rdx
mov    eax,DWORD PTR ds:[rax+0x88]
test   rax,rax
je     jmp2
add    rax,rdx
push   rax
mov    ecx,DWORD PTR ds:[rax+0x18]
mov    r8d,DWORD PTR ds:[rax+0x20]
add    r8,rdx
jmp5:
jrcxz  jmp3
dec    rcx
mov    esi,DWORD PTR ds:[r8+rcx*4]
add    rsi,rdx
xor    r9,r9
jmp4:
xor    rax,rax
lods   al,BYTE PTR ds:[rsi]
ror    r9d,0xd
add    r9d,eax
cmp    al,ah
jne    jmp4
add    r9,QWORD PTR ds:[rsp+0x8]
cmp    r9d,r10d
jne    jmp5
pop    rax
mov    r8d,DWORD PTR ds:[rax+0x24]
add    r8,rdx
mov    cx,WORD PTR ds:[r8+rcx*2]
mov    r8d,DWORD PTR ds:[rax+0x1c]
add    r8,rdx
mov    eax,DWORD PTR ds:[r8+rcx*4]
add    rax,rdx
pop    r8
pop    r8
pop    rsi
pop    rcx
pop    rdx
pop    r8
pop    r9
pop    r10
sub    rsp,0x20
push   r10
jmp    rax
jmp3:
pop    rax
jmp2:
pop    r9
pop    rdx
mov    rdx,QWORD PTR ds:[rdx]
jmp    jmp6
fuc1 :
pop    rbp
mov    r9,0x0
lea    rdx,ds:[rbp+0xfe]
lea    r8,ds:[rbp+0x10f]
xor    rcx,rcx
mov    r10d,0x7568345
call   rbp
xor    rcx,rcx
mov    r10d,0x56a2b5f0
call   rbp

.byte 72,101,108,108,111,44,32,102,114,111,109,32,77,83,70,33,0,77,101,115,115,97,103,101,66,111,120,0
