/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include "sgx_rsrv_mem_mngr.h"

extern int getpagesize(void);

#define FIXED_BUFFER_SIZE (1 << 9)

static os_print_function_t print_function = NULL;

static int getpagesize_impl()
{
	return getpagesize();
}

int bh_platform_init()
{
    return 0;
}

void bh_platform_destroy()
{}

void * wasm_os_malloc(unsigned size)
{
    return malloc(size);
}

void * wasm_os_realloc(void *ptr, unsigned size)
{
    return realloc(ptr, size);
}

void wasm_os_free(void *ptr)
{
    free(ptr);
}

void wasm_os_set_print_function(os_print_function_t pf)
{
    print_function = pf;
}

int wasm_os_printf(const char *message, ...)
{
    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        va_list ap;
        va_start(ap, message);
        vsnprintf(msg, FIXED_BUFFER_SIZE, message, ap);
        va_end(ap);
        print_function(msg);
    }

    return 0;
}

int wasm_os_vprintf(const char *format, va_list arg)
{
    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        vsnprintf(msg, FIXED_BUFFER_SIZE, format, arg);
        print_function(msg);
    }

    return 0;
}

uint64 wasm_os_time_get_boot_microsecond()
{
    return 0;
}

korp_tid wasm_os_self_thread()
{
    return sgx_thread_self();
}

uint8 * wasm_os_thread_get_stack_boundary()
{
    /* TODO: get sgx stack boundary */
    return NULL;
}

int wasm_os_mutex_init(korp_mutex *mutex)
{
    return sgx_thread_mutex_init(mutex, NULL);
}

int wasm_os_mutex_destroy(korp_mutex *mutex)
{
    return sgx_thread_mutex_destroy(mutex);
}

int wasm_os_mutex_lock(korp_mutex *mutex)
{
    return sgx_thread_mutex_lock(mutex);
}

int wasm_os_mutex_unlock(korp_mutex *mutex)
{
    return sgx_thread_mutex_unlock(mutex);
}

#ifdef BH_PLATFORM_LINUX_SGX
void * wasm_os_mmap(void *hint, size_t size, int prot, int flags)
{
    int mprot = 0;
    uint64 aligned_size, page_size;
    void *ret = NULL;
    sgx_status_t st = 0;

    page_size = getpagesize_impl();
    aligned_size = (size + page_size - 1) & ~(page_size - 1);

    if (aligned_size >= UINT32_MAX)
        return NULL;

    ret = sgx_alloc_rsrv_mem(aligned_size);
    if (ret == NULL) {
        wasm_os_printf("os_mmap(size=%u, aligned size=%lu, prot=0x%x) failed.", size,
                  aligned_size, prot);
        return NULL;
    }

    if (prot & MMAP_PROT_READ)
        mprot |= SGX_PROT_READ;
    if (prot & MMAP_PROT_WRITE)
        mprot |= SGX_PROT_WRITE;
    if (prot & MMAP_PROT_EXEC)
        mprot |= SGX_PROT_EXEC;

    st = sgx_tprotect_rsrv_mem(ret, aligned_size, mprot);
    if (st != SGX_SUCCESS) {
        wasm_os_printf("os_mmap(size=%u, prot=0x%x) failed to set protect.", size,
                  prot);
        sgx_free_rsrv_mem(ret, aligned_size);
        return NULL;
    }

    return ret;
}

void wasm_os_munmap(void *addr, size_t size)
{
    uint64 aligned_size, page_size;

    page_size = getpagesize_impl();
    aligned_size = (size + page_size - 1) & ~(page_size - 1);
    sgx_free_rsrv_mem(addr, aligned_size);
}

int wasm_os_mprotect(void *addr, size_t size, int prot)
{
    int mprot = 0;
    sgx_status_t st = 0;
    uint64 aligned_size, page_size;

    page_size = getpagesize_impl();
    aligned_size = (size + page_size - 1) & ~(page_size - 1);

    if (prot & MMAP_PROT_READ)
        mprot |= SGX_PROT_READ;
    if (prot & MMAP_PROT_WRITE)
        mprot |= SGX_PROT_WRITE;
    if (prot & MMAP_PROT_EXEC)
        mprot |= SGX_PROT_EXEC;
    st = sgx_tprotect_rsrv_mem(addr, aligned_size, mprot);
    if (st != SGX_SUCCESS)
        wasm_os_printf("os_mprotect(addr=0x%" PRIx64 ", size=%u, prot=0x%x) failed.",
                  (uintptr_t)addr, size, prot);

    return (st == SGX_SUCCESS ? 0 : -1);
}
#endif

void wasm_os_dcache_flush(void)
{}
