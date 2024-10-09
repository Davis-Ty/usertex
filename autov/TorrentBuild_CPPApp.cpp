//---------------------------------------------------------------------------
//
// Name:        TorrentBuild_CPPApp.cpp
// Author:      Harold Feit
// Created:     5/19/2006 11:09:52 AM
// Description: 
//
//---------------------------------------------------------------------------

#include "TorrentBuild_CPPFunctions.h"
#include "TorrentBuild_CPPApp.h"
#include "TorrentBuild_CPPDlg.h"

IMPLEMENT_APP(TorrentBuild_CPPDlgApp)

bool TorrentBuild_CPPDlgApp::OnInit()
{
	TorrentBuild_CPPDlg* dialog = new TorrentBuild_CPPDlg(NULL);
	SetTopWindow(dialog);
	dialog->Show(true);		
	return true;
}
 
int TorrentBuild_CPPDlgApp::OnExit()
{
	return 0;
}
