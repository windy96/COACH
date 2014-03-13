#ifndef SESCAPI
#define SESCAPI

#include <stdio.h>
#include <stdlib.h>
// is assumed.


//	Invalidation
void	sesc_inv_word(void *addr);
void	sesc_inv_dword(void *addr);
void	sesc_inv_qword(void *addr);
void	sesc_inv_range(void *addr, int size);
void	sesc_inv_all();
void	sesc_inv_master_all();

//	Writeback
void	sesc_wb_word(void *addr);
void	sesc_wb_dword(void *addr);
void	sesc_wb_qword(void *addr);
void	sesc_wb_range(void *addr, int size);
void	sesc_wb_all();
void	sesc_wb_master_all();

//	Writeback & Invalidation
void	sesc_wb_inv_word(void *addr);
void	sesc_wb_inv_dword(void *addr);
void	sesc_wb_inv_qword(void *addr);
void	sesc_wb_inv_range(void *addr, int size);
void	sesc_wb_inv_all();
void	sesc_wb_inv_master_all();

//	Load/Store Bypass
int 	sesc_ld_w_bypass(void *addr);
void	sesc_st_w_bypass(void *addr, int value);

//	[TODO] Writeback Reserve function is not implemented yet.
//	Still in investigation.
void	sesc_wb_reserve(void *addr, int size);

//	[TODO] Writefirst function is not implemented yet.
//	Still in investigation.
void	sesc_wr_first(void *addr, int size);

//	Memory Allocation
void *malloc_pmc(size_t size) __attribute__((noinline));
void *calloc_pmc(size_t nmemb, size_t size) __attribute__((noinline));
void *realloc_pmc(void *ptr, size_t size) __attribute__((noinline));
void free_pmc(void *ptr) __attribute__((noinline));
int posix_memalign_pmc(void **memptr, size_t alignment, size_t size);

//	PMC Thread Functions
typedef struct pmcthread_barrier
{
	int	cur;
	int	count;
	int polarity;
} pmcthread_barrier_t ;

void pmcthread_barrier_init(pmcthread_barrier_t *bar, int *i, int count);
int pmcthread_barrier_wait(pmcthread_barrier_t *bar);
void sesc_memfence(void *ptr);
int pthread_cond_wait_null(void *cond, void *mutex);


void turnoff_check();
void turnon_check();


#endif
