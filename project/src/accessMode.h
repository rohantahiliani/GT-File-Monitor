/* 
 * File:   accessMode.h
 * Author: machiry
 *
 * Created on March 4, 2012, 2:55 AM
 */

#ifndef ACCESSMODE_H
#define	ACCESSMODE_H

#ifdef	__cplusplus
extern "C" {
#endif

enum ACCESSMODE{
        READ=1,
        WRITE=2,
        CREATE=4,
        SYMLINK=8,
        READLINK=16,
        RENAME=32,
        READSTATS=64,
        WRITESTATS=128,
        DELETE=256,
        READWRITE=512,
        EXECUTE=1024
    };


#ifdef	__cplusplus
}
#endif

#endif	/* ACCESSMODE_H */

