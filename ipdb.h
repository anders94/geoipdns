#ifndef IPDB_H
#define IPDB_H
#include <stdio.h>
#include <unistd.h>
#include "stralloc.h"
#include "cdb.h"
#include "uint64.h"
int ipdb_key4build(unsigned char key[16], unsigned int ,unsigned char,uint32,uint32);
int ipdb_key4lookup(unsigned char key[16], unsigned int ,unsigned char,uint32,uint32);
//int ipdb_key_from_uint (unsigned char key[16], unsigned int ,unsigned char, int ,uint32,uint32);
/*
int ipdb_key_from_str (unsigned char key[16], const char *, unsigned char ,  int ,uint32,uint32);
int ipdb_key_from_bytes (unsigned char key[16], unsigned char *,unsigned char , int ,uint32,uint32);
*/
int ipdb_get (struct cdb *, unsigned char ip[4], uint32*,uint32,uint32 );

#endif
