
// #inlucde <stdlib.h>
// is assumed.


//	Invalidation
void	inv_word(void *addr) __attribute__((noinline));
void	inv_word(void *addr)
{ 
	printf("[ERROR] called inv_word for 0x%p, but this should be replaced!\n", addr);
}

void	inv_dword(void *addr) __attribute__((noinline));
void	inv_dword(void *addr)
{ 
	printf("[ERROR] called inv_dword for 0x%p, but this should be replaced!\n", addr);
}

void	inv_qword(void *addr) __attribute__((noinline));
void	inv_qword(void *addr)
{
	printf("[ERROR] called inv_qword for 0x%p, but this should be replaced!\n", addr);
}

void	inv_range(void *addr, int size) __attribute__((noinline));
void	inv_range(void *addr, int size)
{
	printf("[ERROR] called inv_range for 0x%p and 0x%x, but this should be replaced!\n", addr, size);
}


//	Writeback
void	wb_word(void *addr) __attribute__((noinline));
void	wb_word(void *addr)
{ 
	printf("[ERROR] called wb_word for 0x%p, but this should be replaced!\n", addr);
}

void	wb_dword(void *addr) __attribute__((noinline));
void	wb_dword(void *addr)
{ 
	printf("[ERROR] called wb_dword for 0x%p, but this should be replaced!\n", addr);
}

void	wb_qword(void *addr) __attribute__((noinline));
void	wb_qword(void *addr)
{
	printf("[ERROR] called wb_qword for 0x%p, but this should be replaced!\n", addr);
}

void	wb_range(void *addr, int size) __attribute__((noinline));
void	wb_range(void *addr, int size)
{
	printf("[ERROR] called wb_range for 0x%p and 0x%x, but this should be replaced!\n", addr, size);
}


//	Writeback & Invalidation
void	wb_inv_word(void *addr) __attribute__((noinline));
void	wb_inv_word(void *addr)
{ 
	printf("[ERROR] called wb_inv_word for 0x%p, but this should be replaced!\n", addr);
}

void	wb_inv_dword(void *addr) __attribute__((noinline));
void	wb_inv_dword(void *addr)
{ 
	printf("[ERROR] called wb_inv_dword for 0x%p, but this should be replaced!\n", addr);
}

void	wb_inv_qword(void *addr) __attribute__((noinline));
void	wb_inv_qword(void *addr)
{
	printf("[ERROR] called wb_inv_qword for 0x%p, but this should be replaced!\n", addr);
}

void	wb_inv_range(void *addr, int size) __attribute__((noinline));
void	wb_inv_range(void *addr, int size)
{
	printf("[ERROR] called wb_inv_range for 0x%p and 0x%x, but this should be replaced!\n", addr, size);
}


//	Load/Store Bypass
int 	ld_w_bypass(void *addr) __attribute__((noinline));
int 	ld_w_bypass(void *addr)
{
	printf("[ERROR] called ld_w_bypass for 0x%p, but this should be replaced!\n", addr);
	return 0;
}

void	st_w_bypass(void *addr, int value) __attribute__((noinline));
void	st_w_bypass(void *addr, int value)
{
	printf("[ERROR] called st_w_bypass for 0x%p and 0x%x, but this should be replaced!\n", addr, value);
}



//	[TODO] Writeback Reserve function is not implemented yet.
//	Still in investigation.
void	wb_reserve(void *addr, int size) __attribute__((noinline));
void	wb_reserve(void *addr, int size)
{
	printf("[ERROR] called wb_reserve for 0x%p and 0x%x, but this should be replaced!\n", addr, size);
}

//	[TODO] Writefirst function is not implemented yet.
//	Still in investigation.
void	wr_first(void *addr, int size) __attribute__((noinline));
void	wr_first(void *addr, int size)
{
	printf("[ERROR] called wr_first for 0x%p and 0x%x, but this should be replaced!\n", addr, size);
}


//	Memory Allocation
void *malloc_pmc(size_t size) __attribute__((noinline));
void *malloc_pmc(size_t size)
{
	return malloc(size);
}

void *calloc_pmc(size_t size) __attribute__((noinline));
void *calloc_pmc(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}

void *realloc_pmc(size_t size) __attribute__((noinline));
void *realloc_pmc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

void *free_pmc(size_t size) __attribute__((noinline));
void free_pmc(void *ptr)
{
	return free(ptr);
}


//	PMC Thread Functions
typedef struct pmcthread_barrier
{
	int	cur;
	int	count;
	int polarity;
} pmcthread_barrier_t ;


void pmcthread_barrier_init(pmcthread_barrier_t *bar, int *i, int count)
{
	bar->count = count;
	bar->cur = 0;
	bar->polarity = 0;
	asm volatile("" ::: "memory");
}


int pmcthread_barrier_wait(pmcthread_barrier_t *bar)
{
	// Memory fence for entry
	asm volatile("" ::: "memory");
	int temp_polarity;
	bar->cur++;
	temp_polarity = bar->polarity;
	if (bar->cur != bar->count) {
		while (temp_polarity == bar->polarity) ;
		// Memory fence for exit
		asm volatile("" ::: "memory");	
		return 0;
	}
	else {
		bar->cur = 0;
		bar->polarity = bar->polarity ? 0 : 1;
		// Memory fence for exit
		asm volatile("" ::: "memory");	
		return -1;
	}
}


void sesc_memfence(void *ptr)
{

} 

int pthread_cond_wait_null(void *cond, void *mutex) __attribute__((noinline));
int pthread_cond_wait_null(void *cond, void *mutex)
{
	printf("cond_wait_null\n");
	return 0;
}

