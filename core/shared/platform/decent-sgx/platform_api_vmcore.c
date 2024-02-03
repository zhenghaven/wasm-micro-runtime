/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */


#include "platform_api_vmcore.h"


#define FIXED_BUFFER_SIZE (1 << 9)

static os_print_function_t print_function = NULL;

void wasm_os_set_print_function(os_print_function_t pf)
{
    print_function = pf;
}

int bh_platform_init()
{
    return 0;
}

void bh_platform_destroy()
{}

void * os_malloc(unsigned size)
{
    return malloc(size);
}

void * os_realloc(void *ptr, unsigned size)
{
    return realloc(ptr, size);
}

void os_free(void *ptr)
{
    free(ptr);
}

int os_printf(const char *message, ...)
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

int os_vprintf(const char *format, va_list arg)
{
    if (print_function != NULL) {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        vsnprintf(msg, FIXED_BUFFER_SIZE, format, arg);
        print_function(msg);
    }

    return 0;
}

uint64 os_time_get_boot_microsecond()
{
    return 0;
}

int os_mutex_init(korp_mutex *mutex)
{
    return sgx_thread_mutex_init(mutex, NULL);
}

int os_mutex_destroy(korp_mutex *mutex)
{
    return sgx_thread_mutex_destroy(mutex);
}

int os_mutex_lock(korp_mutex *mutex)
{
    return sgx_thread_mutex_lock(mutex);
}

int os_mutex_unlock(korp_mutex *mutex)
{
    return sgx_thread_mutex_unlock(mutex);
}

int os_cond_init(korp_cond *cond)
{
    return sgx_thread_cond_init(cond, NULL);
}

int os_cond_destroy(korp_cond *cond)
{
    return sgx_thread_cond_destroy(cond);
}

int os_cond_wait(korp_cond *cond, korp_mutex *mutex)
{
    return sgx_thread_cond_wait(cond, mutex);
}

int os_cond_reltimedwait(korp_cond *cond, korp_mutex *mutex, uint64 useconds)
{
    os_printf("warning: SGX pthread_cond_timedwait isn't supported, "
              "calling pthread_cond_wait instead!\n");
    return BHT_ERROR;
}

int os_cond_signal(korp_cond *cond)
{
    return sgx_thread_cond_signal(cond);
}

int os_cond_broadcast(korp_cond *cond)
{
    return sgx_thread_cond_broadcast(cond);
}

void os_dcache_flush(void)
{}

void os_icache_flush(void *start, size_t len)
{}

os_file_handle os_get_invalid_handle()
{
    return NULL;
}

int os_dumps_proc_mem_info(char *out, unsigned int size)
{
    return -1;
}

// from linux-sgx sgx_thread.c

uint8 * os_thread_get_stack_boundary()
{
    /* TODO: get sgx stack boundary */
    return NULL;
}

void
os_thread_jit_write_protect_np(bool enabled)
{}
