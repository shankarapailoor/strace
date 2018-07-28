#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define COVER_SIZE (16 << 20)
#define KCOV_TRACE_CMP 1


int do_wait(pid_t pid, const char *name) {
    int status;

	if (waitpid(pid, &status, __WALL) == -1) {
        perror("wait");
        return -1;
    }
    if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) == SIGTRAP) {
            return 0;
        }
        fprintf(stderr, "%s unexpectedly got status %s\n", name, strsignal(status));
        return -1;
    } else if (WIFEXITED(status)) {
        fprintf(stderr, "%s got unexpected status %d\n", name, status);
    }
    return -1;
}

int singlestep(pid_t pid) {
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
        perror("PTRACE_SINGLESTEP");
        return -1;
    }
    return do_wait(pid, "PTRACE_SINGLESTEP");
}

int poke_text(pid_t pid, void *where, void *new_text, void *old_text, size_t len) {
    size_t copied;
    long poke_data, peek_data;
    if (len % sizeof(void *) != 0) {
        fprintf(stderr, "invalid len, not a multiple of %zd\n", sizeof(void *));
        return -1;
    }

	for (copied = 0; copied < len; copied += sizeof(poke_data)) {
        memmove(&poke_data, new_text + copied, sizeof(poke_data));
        if (old_text != NULL) {
            errno = 0;
            peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
            if (peek_data == -1 && errno) {
                perror("PTRACE_PEEKTEXT");
				return -1;
			}
            memmove(old_text + copied, &peek_data, sizeof(peek_data));
        }
		if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
            perror("PTRACE_POKETEXT");
			return -1;
		}
	}
	return 0;
}

static unsigned long setup_kcov(pid_t pid, pid_t parent_pid, unsigned long parent_cover, int *kcov_fd) {
	unsigned long cover_buffer;
	unsigned long file_path;
	struct user_regs_struct new_regs, old_regs;
	uint8_t new_instruction[8];
	uint8_t old_instruction[8];
	int fd;

	char path[32] = "/sys/kernel/debug/kcov\0";

	if (ptrace(PTRACE_GETREGS, pid, NULL, &old_regs)) {
        perror("PTRACE_GETREGS");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

	new_instruction[0] = 0x0f; //syscall
	new_instruction[1] = 0x05; //syscall
	new_instruction[2] = 0xff; //jmp
	new_instruction[3] = 0xe0; //rax


	memmove(&new_regs, &old_regs, sizeof(new_regs));

    //Replace the old instruction with new one and save old instruction
    if (poke_text(pid, (void *) old_regs.rip, new_instruction, old_instruction, sizeof(new_instruction))) {
        goto fail;
    }

    if (*kcov_fd) {
        new_regs.rip = old_regs.rip;
        new_regs.orig_rax = 16;
        new_regs.rax = 16;
        new_regs.rdi = *kcov_fd;
        new_regs.rsi = KCOV_DISABLE;
        new_regs.rdx = 0;

        if (poke_text(pid, (void *) old_regs.rip, new_instruction, NULL, sizeof(new_instruction))) {
            goto fail;
        }

        // set the new registers with our syscall arguments
        if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
            perror("PTRACE_SETREGS");
            goto fail;
        }

        if (singlestep(pid))
            goto fail;


        if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
            perror("PTRACE_GETREGS");
            goto fail;
        }


        new_regs.rip = old_regs.rip;
        new_regs.orig_rax = 3;
        new_regs.rax = 3;
        new_regs.rdi = *kcov_fd;

        if (poke_text(pid, (void *) old_regs.rip, new_instruction, NULL, sizeof(new_instruction))) {
            goto fail;
        }

        // set the new registers with our syscall arguments
        if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
            perror("PTRACE_SETREGS");
            goto fail;
        }

        if (singlestep(pid))
            goto fail;


        if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
            perror("PTRACE_GETREGS");
            goto fail;
        }
    }
    //Mmap memory in tracee for kcov file path
    new_regs.rip = old_regs.rip;
    new_regs.orig_rax = 9; //mmap
    new_regs.rax = 9; //mmap
    new_regs.rdi = 0; //NULL
    new_regs.rsi = PAGE_SIZE; //Length
    new_regs.rdx = PROT_READ | PROT_WRITE; //Protection
    new_regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS; //Flags
    new_regs.r8 = -1; //Fd
    new_regs.r9 = 0; //Offset


    // set the new registers with our syscall arguments
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_SETREGS");
        goto fail;
    }

    if (singlestep(pid))
        goto fail;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_GETREGS");
        return -1;
    }

    //address of mmap for file path
    file_path = (unsigned long)new_regs.rax;

    if ((void *)new_regs.rax == MAP_FAILED) {
        fprintf(stderr, "failed to mmap\n");
        goto fail;
    }

    //write kcov path to tracee's address space
    if (poke_text(pid, (void *) file_path, path, NULL, sizeof(path)))
        fprintf(stderr, "FAILED COPY\n");

    new_regs.rip = old_regs.rip;
    new_regs.orig_rax = 2;
    new_regs.rax = 2;
    new_regs.rdi = file_path;
    new_regs.rsi = O_CREAT|O_RDWR;
    new_regs.rdx = 0;

    if (poke_text(pid, (void *) old_regs.rip, new_instruction, NULL, sizeof(new_instruction)))
        goto fail;

    // set the new registers with our syscall arguments
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_SETREGS");
        goto fail;
    }

    if (singlestep(pid))
        goto fail;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_GETREGS");
        return -1;
    }

    fd = new_regs.rax;
    *kcov_fd = fd;

    //Initialize trace
    new_regs.rip = old_regs.rip;
    new_regs.orig_rax = 16;
    new_regs.rax = 16;
    new_regs.rdi = fd;
    new_regs.rsi = KCOV_INIT_TRACE;
    new_regs.rdx = COVER_SIZE;

    if (poke_text(pid, (void *) old_regs.rip, new_instruction, NULL, sizeof(new_instruction)))
        goto fail;

    // set the new registers with our syscall arguments
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_SETREGS");
        goto fail;
    }

    if (singlestep(pid))
        goto fail;


    if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_GETREGS");
        return -1;
    }

    //Set up cover map in tracee
    new_regs.rip = old_regs.rip;
    new_regs.orig_rax = 9; //MMAP
    new_regs.rax = 9; //Default rax
    new_regs.rdi = 0; //Pointer to the base
    new_regs.rsi = COVER_SIZE*sizeof(unsigned long); //Length
    new_regs.rdx = PROT_READ | PROT_WRITE; //Mode
    new_regs.r10 = MAP_PRIVATE;
    new_regs.r8 =  fd; //kcov file descriptor
    new_regs.r9 = 0;

    if (poke_text(pid, (void *) old_regs.rip, new_instruction, NULL, sizeof(new_instruction)))
        goto fail;

    // set the new registers with our syscall arguments
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_SETREGS");
        goto fail;
    }

    // invoke mmap(2)
    if (singlestep(pid)) {
        goto fail;
    }

	if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_GETREGS");
        return -1;
    }

    // this is the address of the memory we allocated
    cover_buffer = (unsigned long)new_regs.rax;
    if ((void *)new_regs.rax == MAP_FAILED) {
        perror("mmap");
		goto fail;
	}
    //Enable coverage
    new_regs.rip = old_regs.rip;
    new_regs.orig_rax = 16;
    new_regs.rax = 16;
    new_regs.rdi = fd;
    new_regs.rsi = KCOV_ENABLE;
    new_regs.rdx = 0;

    if (poke_text(pid, (void *) old_regs.rip, new_instruction, NULL, sizeof(new_instruction)))
        goto fail;

    // set the new registers with our syscall arguments
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_SETREGS");
        goto fail;
    }

    if (singlestep(pid))
        goto fail;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_GETREGS");
        goto fail;
    }

    new_regs.rip = old_regs.rip;
    new_regs.orig_rax = 11;
    new_regs.rax = 11;
    new_regs.rdi = file_path;
    new_regs.rsi = PAGE_SIZE;

    // set the new registers with our syscall arguments
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_SETREGS");
        goto fail;
    }

    if (singlestep(pid))
        goto fail;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs)) {
        perror("PTRACE_GETREGS");
        return -1;
    }

    //Restore old instruction
    if (poke_text(pid, (void *) old_regs.rip, old_instruction, NULL, sizeof(old_instruction)))
        goto fail;

    //Restore old registers
    //old_regs.rax = old_regs.orig_rax;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &old_regs)) {
        perror("PTRACE_SETREGS");
        goto fail;
    }

	return (unsigned long) cover_buffer;

fail:
	exit(1);
}
