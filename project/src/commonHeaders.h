/* 
 * File:   commonHeaders.h
 * Author: machiry
 *
 * Created on February 25, 2012, 12:13 PM
 */

#ifndef COMMONHEADERS_H
#define	COMMONHEADERS_H

#ifdef	__cplusplus
extern "C" {
#endif
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <malloc.h>
#include <sys/sysctl.h>
#include <asm-generic/fcntl.h>
#include <string.h>
#define null NULL
#define MCHAR 2048
#define TRACE_FAILED -2
#define ATTACH_FAILED -1
#define EXE_FAILED -3
#define long_size sizeof(long)
#define MAXKBUFF 4096
#ifdef	__cplusplus
}
#endif

#endif	/* COMMONHEADERS_H */

