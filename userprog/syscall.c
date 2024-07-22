#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

// add
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <list.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

struct page * check_address(void * addr);

void halt (void);
void exit (int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);

int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);

int _write (int fd UNUSED, const void *buffer, unsigned size);

void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int dup2(int oldfd, int newfd);

tid_t fork(const char *thread_name, struct intr_frame *f);
int exec(char *file_name);

// 2-4 file descriptor
static struct file *find_file_by_fd(int fd);
int add_file_to_fdt(struct file *file);
void remove_file_from_fdt(int fd);

// 2-extra
#define STDIN 1
#define STDOUT 2

void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
	lock_init(&file_rw_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	switch(f->R.rax) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			if(exec(f->R.rdi)==-1)
				exit(-1);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 1);
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 0);
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		case SYS_DUP2:
			f->R.rax = dup2(f->R.rdi, f->R.rsi);
			break;
		case SYS_MMAP:
			f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		case SYS_MUNMAP:
			munmap(f->R.rdi);
			break;
		default:
			exit(-1);
			break;
	}
	// printf ("system call!\n");
	// thread_exit ();
}

struct page * check_address(void * addr) {
	if (addr == NULL || is_kernel_vaddr(addr)) {
		exit(-1);
	}

	return spt_find_page(&thread_current()->spt, addr);
}

void check_valid_buffer(void *buffer, unsigned size, void *rsp, bool to_write) {
	for (int i = 0; i < size; i++) {
		struct page *page = check_address(buffer + i);
		
		/* 해당 주소가 포함된 페이지가 spt에 없는 경우 */
		if (page == NULL) {
			exit(-1);
		}

		/* write 시스템 콜을 호출했는데 쓰기가 허용되지 않는 페이지인 경우 */
		if (to_write == true && page->writable == false) {
			exit(-1);
		}
	}
}

void
halt(void) {
	power_off();
}

void
exit(int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

bool 
create(const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);
}

bool
remove(const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int
open(const char *file) {
	check_address(file);
	struct file *fileobj = filesys_open(file);

	if(fileobj == NULL)
		return -1;
	
	int fd = add_file_to_fdt(fileobj);

	if(fd == -1)
		file_close(fileobj);
	
	return fd;
}

int
filesize(int fd) {
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;
	return file_length(fileobj);
}

int
read(int fd, void *buffer, unsigned size) {
	check_address(buffer);
	int ret;
	struct thread *cur = thread_current();

	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;

	// fd 0 reads from the keyboard using input_getc().
	// 왜 fd == 0 인 조건은 안될까?
	if (fileobj == STDIN)
	{
		// stdin device와의 연결이 해제(close)되어 있을 경우 stdin_count == 0
		if (cur->stdin_count == 0)
		{
			// Not reachable
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		}
		else
		{
			int i;
			unsigned char *buf = buffer;
			for (i = 0; i < size; i++)
			{
				// input_getc는 한글자 씩 buffer에서 혹은 buffer가 비었다면 key가 눌리길 기다린다.
				char c = input_getc();
				// 주소를 1씩 올려가며 차례대로 buffer에 한글자씩 담는다.
				*buf++ = c;
				if (c == '\0')
					break;
			}
			ret = i;
		}
	}
	else if (fileobj == STDOUT)
	{
		ret = -1;
	}
	else //일반적인 파일을 읽는다면
	{
		// file_rw_lock defined in syscall.h
		// Q. read는 동시접근 허용해도 되지 않을까?
		lock_acquire(&file_rw_lock);
		// Reads SIZE bytes from FILE into BUFFER
		ret = file_read(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}
	return ret;
}

int 
write(int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	int ret;

	struct file *fileobj = find_file_by_fd(fd);
	if(fileobj==NULL)
		return -1;
	
	struct thread *cur = thread_current();

	if(fileobj == STDOUT) {
		if(cur->stdout_count==0){
			// Not reached;
			NOT_REACHED();
			remove_file_from_fdt(fd);
			ret = -1;
		} else {
			putbuf(buffer, size);
			ret = size;
		}
	} else if(fileobj == STDIN) {
		ret = -1;
	} else {
		lock_acquire(&file_rw_lock);
		ret = file_write(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}

	return ret;
}

void
seek(int fd, unsigned position) {
	struct file *fileobj = find_file_by_fd(fd);
	// stdin, stdout 은 무시
	if (fileobj <= 2)
		return;
	fileobj->pos = position;
}

unsigned 
tell(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	// stdin, stdout 은 무시
	if (fileobj <= 2)
		return;
	return file_tell(fileobj);
}

void
close(int fd) {
	struct file *fileobj = find_file_by_fd(fd);
	if(fileobj == NULL)
		return;
	
	struct thread *curr = thread_current();
	//fd 0, 1은 각각 stdin, stdout.
	if (fd == 0 || fileobj == STDIN)
	{
		curr->stdin_count--;
	}
	else if (fd == 1 || fileobj == STDOUT)
	{
		curr->stdout_count--;
	}

	// fd table에서 [fd]의 값을 NULL로 초기화
	remove_file_from_fdt(fd);

	//만약 stdin, stdout 호출이였으면 여기서 마무리
	if (fd <= 1 || fileobj <= 2)
		return;

	//fd가 일반 파일을 가리킬 경우 file_close 호출
	if (fileobj -> dupCount == 0)
		file_close(fileobj);
	else
		fileobj->dupCount--;
}

int dup2(int oldfd, int newfd) {
	if(oldfd == newfd) 
		return newfd;
	
	struct file *fileobj = find_file_by_fd(oldfd);
	if(fileobj==NULL)
		return;
	
	struct thread *curr = thread_current();
	struct file **fdt = curr->fdTable;

	// do not copy, just share same file
	if(fileobj == STDIN) {
		curr->stdin_count++;
	} else if(fileobj==STDOUT) {
		curr->stdout_count++;
	} else {
		fileobj->dupCount++;
	}

	close(newfd);
	fdt[newfd] = fileobj;
	return newfd;
}

tid_t 
fork(const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}

int
exec(char *file_name) {
	struct thread *cur = thread_current();
	check_address(file_name);

	int siz = strlen(file_name) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if(fn_copy == NULL)
		exit(-1);
	strlcpy(fn_copy, file_name, siz);

	if(process_exec(fn_copy)==-1)
		return -1;
	
	NOT_REACHED();
	return 0;
}

static struct file *
find_file_by_fd(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return NULL;

	return cur->fdTable[fd]; // automatically returns NULL if empty
}

// Find open spot in current thread's fdt and put file in it. Returns the fd.
// fdt = file descriptor table
int add_file_to_fdt(struct file *file)
{
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable; // file descriptor table

	/* Project2-extra - (multi-oom) Find open spot from the front
	 *  1. 확보가능한 fd 번호 (fdIdx)가 limit 보다 작고, 
	 *  2. fdt[x] 에 값이 있다면 while문 계속 진행
	 * 결과적으로 fdt[x]가 NULL값을 리턴 할 때 while 문을 탈출한다. = 빈 자리. */ 
	while ((cur->fdIdx < FDCOUNT_LIMIT) && fdt[cur->fdIdx])
		cur->fdIdx++;

	// Error - fdt full
	if (cur->fdIdx >= FDCOUNT_LIMIT)
		return -1;

	// 빈 fd에 file의 주소를 기록해준다.
	fdt[cur->fdIdx] = file;
	return cur->fdIdx;
}

// Check for valid fd and do cur->fdTable[fd] = NULL. Returns nothing
void remove_file_from_fdt(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	cur->fdTable[fd] = NULL;
}

void *mmap (void *addr, size_t length, int writable, int fd, off_t offset){
	// Fail : map to i/o console, zero length, map at 0, addr not page-aligned
	if(fd == 0 || fd == 1 || length == 0 || addr == 0 || pg_ofs(addr) != 0 || offset > PGSIZE)
		return NULL;

	// Find file by fd
	struct file *file = find_file_by_fd(fd);	

	// Fail : NULL file, file length is zero
	if (file == NULL || file_length(file) == 0)
		return NULL;

	return do_mmap(addr, length, writable, file, offset);
}

// Project 3-3 mmap
void munmap (void *addr){
	do_munmap(addr);
}