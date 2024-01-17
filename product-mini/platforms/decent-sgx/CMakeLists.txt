# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.0)

project (iwasm LANGUAGES C ASM)

if (WIN32)
  enable_language(ASM_MASM)
endif()

set (WAMR_BUILD_PLATFORM "decent-sgx")

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Set WAMR_BUILD_TARGET
if (NOT DEFINED WAMR_BUILD_TARGET)
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # Build as X86_64 by default in 64-bit platform
    set (WAMR_BUILD_TARGET "X86_64")
  else ()
    # Build as X86_32 by default in 32-bit platform
    set (WAMR_BUILD_TARGET "X86_32")
  endif ()
endif ()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif ()

if (NOT DEFINED WAMR_BUILD_INTERP)
  # Enable Interpreter by default
  set (WAMR_BUILD_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_AOT)
  if (NOT WIN32)
    # Enable AOT by default
    # Please install Intel SGX SDKv2.8 or later.
    set (WAMR_BUILD_AOT 1)
  else ()
    # Disable AOT by default for Windows since implementations for
    # platform_api_vmcore.h section 2 are missing.
    set (WAMR_BUILD_AOT 0)
  endif ()
endif ()

if (NOT DEFINED WAMR_BUILD_JIT)
  # Disable JIT by default.
  set (WAMR_BUILD_JIT 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  # Enable libc builtin support by default
  set (WAMR_BUILD_LIBC_BUILTIN 1)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_WASI)
  # Enable libc wasi support by default
  set (WAMR_BUILD_LIBC_WASI 0)
endif ()

if (NOT DEFINED WAMR_BUILD_FAST_INTERP)
  # Enable fast interpreter
  set (WAMR_BUILD_FAST_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_MULTI_MODULE)
  # Enable multiple modules
  set (WAMR_BUILD_MULTI_MODULE 1)
endif ()

if (NOT DEFINED WAMR_BUILD_LIB_PTHREAD)
  # Enable pthread library by default
  set (WAMR_BUILD_LIB_PTHREAD 0)
endif ()

if (MSVC)
  STRING (REGEX REPLACE "/RTC(su|[1su])" ""
    CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
  STRING (REGEX REPLACE "/RTC(su|[1su])" ""
    CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
  STRING (REGEX REPLACE "/RTC(su|[1su])" ""
    CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
  STRING (REGEX REPLACE "/RTC(su|[1su])" ""
    CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
endif()

if (UNIX)
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -ffunction-sections -fdata-sections \
                                       -Wall -Wno-unused-parameter -Wno-pedantic \
                                       -nostdinc -fvisibility=hidden -fpie" )
endif()

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

add_library(vmlib_decent_sgx ${WAMR_RUNTIME_LIB_SOURCE})

target_include_directories(vmlib_decent_sgx
                            PUBLIC ${WAMR_ROOT_DIR}/core/iwasm/include)

if (WIN32)
  target_compile_definitions(vmlib_decent_sgx
                              PUBLIC COMPILING_WASM_RUNTIME_API=1)
endif()
