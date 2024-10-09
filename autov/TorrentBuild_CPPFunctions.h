//---------------------------------------------------------------------------
//
// Name:        TorrentBuild_CPPFunctions.h
// Author:      Harold Feit
// Created:     5/19/2006 11:09:52 AM
// Description: 
//
//---------------------------------------------------------------------------

#include "atom.h"
#include "bencode.h"

#ifndef __TorrentBuild_CPPFunctions_h__
#define __TorrentBuild_CPPFunctions_h__

__int64 FileSize(const char* sFileName);
CAtom *GetConfig();
int GetAutoPieceSize ( unsigned long TotalSize );
#ifdef WIN32
 #define MILLISLEEP( x ) Sleep( x )
#else
 #define MILLISLEEP( x ) usleep( ( x ) * 1000 )
#endif
#endif
