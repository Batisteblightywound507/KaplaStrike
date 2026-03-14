/*
 * Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* NB This is a slightly modified version of `debug.h` in tcg/simple_rdll_mask (tcg20250910-bsd). */
 
/* Set to 1 to get dprintf for *PIC* (or use LOADER_DEBUG in definitions.h) */
#define PIC_DEBUG 0
#if !defined(LOADER_DEBUG)
#define LOADER_DEBUG 0
#endif

/*
 * Save you some headache doing a PIC printf for debugging
 */

 #ifndef WIN32_FUNC
 #define WIN32_FUNC( x ) __typeof__( x ) * x
 #endif
  
 typedef int __cdecl (*vsnprintf_t)(char * d, size_t n, char * format, ...);
  
 typedef struct {
     WIN32_FUNC(VirtualAlloc);
     WIN32_FUNC(VirtualFree);
     WIN32_FUNC(OutputDebugStringA);
     vsnprintf_t vsnprintf;
 } DPRINTFFUNCS;

 #if (PIC_DEBUG || LOADER_DEBUG)
  
 void dprintf(IMPORTFUNCS * ifuncs, char * format, ...) {
     va_list args;
     HMODULE mod;
  
     DPRINTFFUNCS funcs;
  
     char kern32[] = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', 0 };
     char vastr[]  = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
     char vfstr[]  = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0 };
     char odstr[]  = { 'O', 'u', 't', 'p', 'u', 't', 'D', 'e', 'b', 'u', 'g', 'S', 't', 'r', 'i', 'n', 'g', 'A', 0 };
  
     char msvcrt[] = { 'M', 'S', 'V', 'C', 'R', 'T', 0 };
     char pfstr[]  = { 'v', 's', 'n', 'p', 'r', 'i', 'n', 't', 'f', 0 };
  
     mod                      = ifuncs->LoadLibraryA(kern32);
     funcs.VirtualAlloc       = (__typeof__(VirtualAlloc) *)      ifuncs->GetProcAddress(mod, vastr);
     funcs.VirtualFree        = (__typeof__(VirtualFree) *)       ifuncs->GetProcAddress(mod, vfstr);
     funcs.OutputDebugStringA = (__typeof__(OutputDebugStringA) *)ifuncs->GetProcAddress(mod, odstr);
  
     mod                      = ifuncs->LoadLibraryA(msvcrt);
     funcs.vsnprintf          = (vsnprintf_t)                     ifuncs->GetProcAddress(mod, pfstr);
  
     va_start(args, format);
     __dprintf(&funcs, format, &args);
     va_end(args);
 }
#else
#define dprintf(ifuncs, format, ...)
#endif