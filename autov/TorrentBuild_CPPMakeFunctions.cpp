
#include "SHA1.h"
#include "atom.h"
#include "bencode.h"
#include "util.h"
#include "stringsplit.h"
#include <stdio.h>
#include <stdlib.h>

#include "TorrentBuild_CPPFunctions.h"
#include "TorrentBuild_CPPDlg.h"
#include "TorrentBuild_CPP_private.h"
#include <cstdlib>
#include <iostream>
#include <fstream>
#include "src_algo/crc32.h"

void TorrentBuild_CPPDlg::MakeTorrentFromFile( string fileToMake , int pieceSize, string announceurl, CAtom *announcelist,
string comment, bool privateTorrent, bool gensha1, bool gencrc32,
bool genmd5, bool gened2k, bool gentth, bool genexternals)
{
     CAtomDicti *pTorrentRoot = new CAtomDicti();
     CAtomDicti *pTorrentInfo = new CAtomDicti();
     pTorrentRoot->setItem( "info" , pTorrentInfo );
     vector<string> sFileName;
     StringUtils::SplitString( fileToMake, "\\", sFileName, false);
     pTorrentInfo->setItem( "name", new CAtomString( sFileName[sFileName.size()-1] ) );
     pTorrentInfo->setItem( "length", new CAtomLong( FileSize( fileToMake.c_str() ) ) );
     pTorrentInfo->setItem( "piece length", new CAtomLong( pieceSize ) );
     if( privateTorrent == true )
          pTorrentInfo->setItem( "private", new CAtomLong( 1 ) );
     if( announceurl != string() )
          pTorrentRoot->setItem( "announce", new CAtomString( announceurl ) );
     if( comment != string () )
          pTorrentRoot->setItem( "comment", new CAtomString( comment ) );
     if( announcelist && announcelist->isList() )
          pTorrentRoot->setItem( "announce-list", announcelist );
     
     // Begin Optional Hashing
     
     int OptionalHashes = 0;
     if( gensha1 == true )
     {
         CSHA1 *filesha1 = new CSHA1();
         filesha1->HashFile( (char *)(fileToMake.c_str()) );
         filesha1->Final();
         char filehash[40];
       	 memset( filehash, 0, sizeof( char ) * 40 );
         filesha1->ReportHash( filehash );
         pTorrentInfo->setItem( "sha1", new CAtomString( UTIL_StringToHash ( string( filehash ) ) ) );
         OptionalHashes++;
         OptionalHashProgress->SetValue( OptionalHashes );
         Refresh();
         Update();
     }
     if( gencrc32 == true )
     {
         CCRC32Hash *fileCRC32 = new CCRC32Hash();
         fileCRC32->HashFile( (char *)(fileToMake.c_str()) );
         fileCRC32->Final();
         char fileCRChash[8];
       	 memset( fileCRChash, 0, sizeof( char ) * 8 );
         fileCRC32->ReportHash( fileCRChash );
         pTorrentInfo->setItem( "crc32", new CAtomString( string( fileCRChash ) ) );
         OptionalHashes++;
         OptionalHashProgress->SetValue( OptionalHashes );
         Refresh();
         Update();
     }
     /*     if( genmd5 == true )
     {
         MD5 *filemd5 = new MD5();
         FILE *fIn;
         fIn = fopen(fileToMake.c_str(), "rb");
         //if(fIn == NULL) return false;
         filemd5->update( fIn );
         filemd5->finalize();
         pTorrentInfo->setItem( "md5", new CAtomString( UTIL_StringToHash ( string( filemd5->hex_digest() ) ) ) );
         OptionalHashes++;
         OptionalHashProgress->SetValue( OptionalHashes );
     }
*/

     // Begin File Piece Hashing
   	 FILE *filetoopen;
 	 filetoopen = fopen( fileToMake.c_str() , "rb" );
 	 string pieces = string();
   	 int piececount = 0;
   	 bool breaknow = false;
     char * pieceobtained;
   	 PieceHashProgress->SetValue(0);
 	 while ( true )
     {
         CSHA1 *piecesha1 = new CSHA1();
   	     piecesha1->Reset();
         int newSize = pieceSize;
         PieceHashProgress->SetValue( ( (pieceSize * piececount) /FileSize(fileToMake.c_str()) ) * 100 );
         Refresh();
         Update();
         if( FileSize( fileToMake.c_str() ) - (pieceSize * piececount) < pieceSize )
         {
             newSize = FileSize( fileToMake.c_str() ) - (pieceSize * piececount);
             breaknow = true;
         }
         if( FileSize( fileToMake.c_str() ) - (pieceSize * piececount) == 0) break;
         UINT_8 memblock[newSize];
    	 fread( memblock,1, newSize, filetoopen );
     	 piecesha1->Update(memblock, newSize);
     	 piecesha1->Final();
     	 pieceobtained = new char[40];
       	 memset( pieceobtained, 0, sizeof( char ) * 40 );
     	 piecesha1->ReportHash( pieceobtained );
   	     pieces = pieces + UTIL_StringToHash ( string( pieceobtained ) );
     	 piececount++;
     	 //filetoopen.seekg(piececount*pieceSize, ios::beg);
     	 if( breaknow == true) break;
     }
     PieceHashProgress->SetValue(100);
     fclose(filetoopen);
     pTorrentRoot->setItem("created by", new CAtomString( string( FILE_DESCRIPTION ) + string(" ") + string (VER_STRING ) ) );
     pTorrentInfo->setItem("pieces", new CAtomString( pieces ) );
     string pathForTorrent = fileToMake + string(".torrent");
     UTIL_MakeFile( pathForTorrent.c_str() , Encode( pTorrentRoot ) );
}
