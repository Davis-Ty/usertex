//---------------------------------------------------------------------------
//
// Name:        TorrentBuild_CPPApp.h
// Author:      Harold Feit
// Created:     5/19/2006 11:09:52 AM
// Description: 
//
//---------------------------------------------------------------------------

#include "atom.h"
#include "bencode.h"

#ifndef __TorrentBuild_CPPApp_h__
#define __TorrentBuild_CPPApp_h__

#ifdef __BORLANDC__
	#pragma hdrstop
#endif

#ifndef WX_PRECOMP
	#include <wx/wx.h>
#else
	#include <wx/wxprec.h>
#endif

class TorrentBuild_CPPDlgApp : public wxApp
{
	public:
		bool OnInit();
		int OnExit();
};

#endif
