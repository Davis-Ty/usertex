//---------------------------------------------------------------------------
//
// Name:        TorrentBuild_CPPFunctions.cpp
// Author:      Harold Feit
// Created:     5/19/2006 11:09:52 AM
// Description: 
//
//---------------------------------------------------------------------------


#include "atom.h"
#include "bencode.h"

#include "util.h"
#include "stringsplit.h"

#include "SHA1.h"
#include "TorrentBuild_CPPFunctions.h"

#include <cstdlib>
#include <iostream>
#include <fstream>

__int64 FileSize(const char* sFileName)
{
  std::ifstream f;
  f.open(sFileName, std::ios_base::binary | std::ios_base::in);
  if (!f.good() || f.eof() || !f.is_open()) { return 0; }
  f.seekg(0, std::ios_base::beg);
  std::ifstream::pos_type begin_pos = f.tellg();
  f.seekg(0, std::ios_base::end);
  return static_cast<int>(f.tellg() - begin_pos);
}


int GetAutoPieceSize ( unsigned long TotalSize )
{
    int64 fiftymeg = 50*1024*1024;
    int64 onefiftymeg = 150*1024*1024;
    int64 threefiftymeg = 350*1024*1024;
    int64 halfgig = 512*1024*1024;
    int64 onegig = 1024*1024*1024;
    int64 twogig = 2048*1024*1024;

    if( TotalSize < fiftymeg )
         return ( 32768 );
    else if ( TotalSize < onefiftymeg )
         return ( 65536 );
    else if ( TotalSize < threefiftymeg )
         return ( 131072 );
    else if ( TotalSize < halfgig )
         return ( 262144 );
    else if ( TotalSize < onegig )
         return ( 524288 );
    else if ( TotalSize < twogig )
         return ( 1048576 );
    else
         return ( 2097152 );
}

CAtom *GetConfig()
{
      return DecodeFile( "tgen.configure" );      
}
