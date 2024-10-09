//---------------------------------------------------------------------------
//
// Name:        TorrentBuild_CPPDlg.cpp
// Author:      Harold Feit
// Created:     5/19/2006 11:09:52 AM
// Description: 
//
//---------------------------------------------------------------------------

#include "TorrentBuild_CPPApp.h"

#include "atom.h"
#include "bencode.h"
#include "util.h"
#include "stringsplit.h"

#include "TorrentBuild_CPPFunctions.h"
#include "TorrentBuild_CPPDlg.h"

//Do not add custom headers
//wxDev-C++ designer will remove them
////Header Include Start
#include "TorrentBuild_CPPDlg_XPM.xpm"
////Header Include End

//----------------------------------------------------------------------------
// TorrentBuild_CPPDlg
//----------------------------------------------------------------------------
//Add Custom Events only in the appropriate block.
//Code added in other places will be removed by wxDev-C++
////Event Table Start
BEGIN_EVENT_TABLE(TorrentBuild_CPPDlg,wxDialog)
	////Manual Code Start
	////Manual Code End
	
	EVT_CLOSE(TorrentBuild_CPPDlg::TorrentBuild_CPPDlgClose)
	EVT_BUTTON(ID_SAVESETTINGS,TorrentBuild_CPPDlg::SaveSettingsClick)
	EVT_BUTTON(ID_EXITWITHSAVE,TorrentBuild_CPPDlg::ExitWithSaveClick)
	EVT_BUTTON(ID_EXITWITHOUTSAVE,TorrentBuild_CPPDlg::ExitWithoutSaveClick)
	EVT_BUTTON(ID_BUILDTORRENTNOW,TorrentBuild_CPPDlg::BuildTorrentNowClick)
	EVT_CHECKBOX(ID_AUTOMATICPIECESIZE,TorrentBuild_CPPDlg::AutomaticPieceSizeClick)
	EVT_BUTTON(ID_SELECTFOLDER,TorrentBuild_CPPDlg::SelectFolderClick)
	EVT_BUTTON(ID_SELECTFILE,TorrentBuild_CPPDlg::SelectFileClick)
END_EVENT_TABLE()
////Event Table End

TorrentBuild_CPPDlg::TorrentBuild_CPPDlg(wxWindow *parent, wxWindowID id, const wxString &title, const wxPoint &position, const wxSize& size, long style)
: wxDialog(parent, id, title, position, size, style)
{
    CreateGUIControls();
    LoadConfigValues();
    if( AutomaticPieceSize->GetValue() == true )
        PieceSize->Enable(false);
    else
        PieceSize->Enable(true);
}

TorrentBuild_CPPDlg::~TorrentBuild_CPPDlg() {} 

void TorrentBuild_CPPDlg::CreateGUIControls(void)
{
    //Do not add custom code here
	//wxDev-C++ designer will remove them.
	//Add the custom code before or after the blocks
	////GUI Items Creation Start

	this->SetSize(8,8,512,476);
	this->SetTitle(wxT("Build A Torrent"));
	this->Center();
	wxIcon TorrentBuild_CPPDlg_ICON (TorrentBuild_CPPDlg_XPM);
	this->SetIcon(TorrentBuild_CPPDlg_XPM);
	

	BrowseForFolder =  new wxDirDialog(this, wxT("Choose a directory"), wxT(""));

	BrowseForFile =  new wxFileDialog(this, wxT("Choose a file to make a torrent of"), wxT(""), wxT(""), wxT("*.*"), wxOPEN | wxFILE_MUST_EXIST);

	WxStaticText8 = new wxStaticText(this, ID_WXSTATICTEXT8, wxT("Torrent Comment"), wxPoint(0,184), wxSize(85,16), wxST_NO_AUTORESIZE, wxT("WxStaticText8"));

	MultiTrackerEnabled = new wxCheckBox(this, ID_MULTITRACKERENABLED, wxT("Multitracker Torrent"), wxPoint(376,144), wxSize(128,16), 0, wxDefaultValidator, wxT("MultiTrackerEnabled"));
	MultiTrackerEnabled->Enable(false);

	TorrentComment = new wxTextCtrl(this, ID_TORRENTCOMMENT, wxT(""), wxPoint(0,200), wxSize(504,21), 0, wxDefaultValidator, wxT("TorrentComment"));

	AdvSet = new wxButton(this, ID_ADVSET, wxT("Advanced Settings"), wxPoint(0,400), wxSize(144,24), 0, wxDefaultValidator, wxT("AdvSet"));
	AdvSet->Enable(false);

	SaveSettings = new wxButton(this, ID_SAVESETTINGS, wxT("Save All Settings"), wxPoint(0,424), wxSize(144,24), 0, wxDefaultValidator, wxT("SaveSettings"));

	ExitWithSave = new wxButton(this, ID_EXITWITHSAVE, wxT("Exit - Save Settings"), wxPoint(360,424), wxSize(144,24), 0, wxDefaultValidator, wxT("ExitWithSave"));

	ExitWithoutSave = new wxButton(this, ID_EXITWITHOUTSAVE, wxT("Exit - Don't Save Settings"), wxPoint(360,400), wxSize(144,24), 0, wxDefaultValidator, wxT("ExitWithoutSave"));

	MultitrackerSettings = new wxButton(this, ID_MULTITRACKERSETTINGS, wxT("Multitracker Settings"), wxPoint(376,160), wxSize(128,24), 0, wxDefaultValidator, wxT("MultitrackerSettings"));
	MultitrackerSettings->Enable(false);

	BlacklistingScreen = new wxButton(this, ID_BLACKLISTINGSCREEN, wxT("Blacklisted Files/Extensions"), wxPoint(296,120), wxSize(208,24), 0, wxDefaultValidator, wxT("BlacklistingScreen"));
	BlacklistingScreen->Enable(false);

	IncludeBlacklisted = new wxCheckBox(this, ID_INCLUDEBLACKLISTED, wxT("Include normally blacklisted files in generation"), wxPoint(176,104), wxSize(328,16), 0, wxDefaultValidator, wxT("IncludeBlacklisted"));
	IncludeBlacklisted->Enable(false);

	IncludeTorrents = new wxCheckBox(this, ID_INCLUDETORRENTS, wxT("Include nested .torrent files in generation"), wxPoint(176,88), wxSize(328,16), 0, wxDefaultValidator, wxT("IncludeTorrents"));
	IncludeTorrents->Enable(false);

	MakeSeparateTorrents = new wxCheckBox(this, ID_MAKESEPARATETORRENTS, wxT("Generate 1 Torrent per file"), wxPoint(176,72), wxSize(328,16), 0, wxDefaultValidator, wxT("MakeSeparateTorrents"));
	MakeSeparateTorrents->Enable(false);

	PieceHashProgress = new wxGauge(this, ID_PIECEHASHPROGRESS, 100, wxPoint(0,384), wxSize(504,16), wxGA_HORIZONTAL, wxDefaultValidator, wxT("PieceHashProgress"));
	PieceHashProgress->SetRange(100);
	PieceHashProgress->SetValue(0);

	HashProgress = new wxGauge(this, ID_HASHPROGRESS, 100, wxPoint(0,352), wxSize(504,16), wxGA_HORIZONTAL, wxDefaultValidator, wxT("HashProgress"));
	HashProgress->SetRange(100);
	HashProgress->SetValue(0);

	OptionalHashProgress = new wxGauge(this, ID_OPTIONALHASHPROGRESS, 100, wxPoint(0,320), wxSize(504,16), wxGA_HORIZONTAL, wxDefaultValidator, wxT("OptionalHashProgress"));
	OptionalHashProgress->SetRange(100);
	OptionalHashProgress->SetValue(0);

	WxStaticText7 = new wxStaticText(this, ID_WXSTATICTEXT7, wxT("Progress - Torrent Data Hashing"), wxPoint(0,368), wxSize(156,16), wxST_NO_AUTORESIZE, wxT("WxStaticText7"));

	WxStaticText6 = new wxStaticText(this, ID_WXSTATICTEXT6, wxT("Progress - Current file's ED2K hash"), wxPoint(0,336), wxSize(168,16), wxST_NO_AUTORESIZE, wxT("WxStaticText6"));

	WxStaticText5 = new wxStaticText(this, ID_WXSTATICTEXT5, wxT("Progress - Optional Data Hashes"), wxPoint(0,304), wxSize(160,16), wxST_NO_AUTORESIZE, wxT("WxStaticText5"));

	BuildTorrentNow = new wxButton(this, ID_BUILDTORRENTNOW, wxT("Build Torrent"), wxPoint(360,272), wxSize(144,25), 0, wxDefaultValidator, wxT("BuildTorrentNow"));
	BuildTorrentNow->SetDefault();

	MakeExternals = new wxCheckBox(this, ID_MAKEEXTERNALS, wxT("Make External Hash Files"), wxPoint(0,272), wxSize(216,16), 0, wxDefaultValidator, wxT("MakeExternals"));
	MakeExternals->Enable(false);

	MakeTiger = new wxCheckBox(this, ID_MAKETIGER, wxT("TTH"), wxPoint(144,240), wxSize(72,16), 0, wxDefaultValidator, wxT("MakeTiger"));
	MakeTiger->Enable(false);

	MakeED2K = new wxCheckBox(this, ID_MAKEED2K, wxT("ED2K"), wxPoint(72,256), wxSize(72,16), 0, wxDefaultValidator, wxT("MakeED2K"));
	MakeED2K->Enable(false);

	MakeSHA1 = new wxCheckBox(this, ID_MAKESHA1, wxT("SHA1"), wxPoint(0,256), wxSize(72,16), 0, wxDefaultValidator, wxT("MakeSHA1"));

	MakeCRC32 = new wxCheckBox(this, ID_MAKECRC32, wxT("CRC32"), wxPoint(72,240), wxSize(72,16), 0, wxDefaultValidator, wxT("MakeCRC32"));
	MakeCRC32->Enable(false);

	MakeMD5 = new wxCheckBox(this, ID_MD5, wxT("MD5"), wxPoint(0,240), wxSize(72,16), 0, wxDefaultValidator, wxT("MakeMD5"));
	MakeMD5->Enable(false);

	WxStaticText4 = new wxStaticText(this, ID_WXSTATICTEXT4, wxT("Optional hashes (Used by non-torrent peer to peer networks):"), wxPoint(0,224), wxSize(300,16), wxST_NO_AUTORESIZE, wxT("WxStaticText4"));

	PrivateTorrent = new wxCheckBox(this, ID_PRIVATETORRENT, wxT("Private Torrent"), wxPoint(400,224), wxSize(104,16), 0, wxDefaultValidator, wxT("PrivateTorrent"));

	AnnounceURL = new wxTextCtrl(this, ID_ANNOUNCEURL, wxT(""), wxPoint(0,160), wxSize(376,21), 0, wxDefaultValidator, wxT("AnnounceURL"));

	WxStaticText3 = new wxStaticText(this, ID_WXSTATICTEXT3, wxT("Announce URL:"), wxPoint(0,144), wxSize(81,16), wxST_NO_AUTORESIZE, wxT("WxStaticText3"));

	AutomaticPieceSize = new wxCheckBox(this, ID_AUTOMATICPIECESIZE, wxT("Automatic Piece Size"), wxPoint(0,112), wxSize(136,16), 0, wxDefaultValidator, wxT("AutomaticPieceSize"));
	AutomaticPieceSize->SetValue(true);

	wxArrayString arrayStringFor_PieceSize;
	arrayStringFor_PieceSize.Add(wxT("32768"));
	arrayStringFor_PieceSize.Add(wxT("65536"));
	arrayStringFor_PieceSize.Add(wxT("121072"));
	arrayStringFor_PieceSize.Add(wxT("262144"));
	arrayStringFor_PieceSize.Add(wxT("524288"));
	arrayStringFor_PieceSize.Add(wxT("1048576"));
	arrayStringFor_PieceSize.Add(wxT("2097152"));
	PieceSize = new wxComboBox(this, ID_PIECESIZE, wxT("262144"), wxPoint(0,88), wxSize(120,21), arrayStringFor_PieceSize, 0, wxDefaultValidator, wxT("PieceSize"));
	PieceSize->Enable(false);

	WxStaticText2 = new wxStaticText(this, ID_WXSTATICTEXT2, wxT("Piece Size"), wxPoint(0,72), wxSize(54,16), wxST_NO_AUTORESIZE, wxT("WxStaticText2"));

	SelectFolder = new wxButton(this, ID_SELECTFOLDER, wxT("Select Folder To Generate Torrent For"), wxPoint(248,48), wxSize(256,24), 0, wxDefaultValidator, wxT("SelectFolder"));

	SelectFile = new wxButton(this, ID_SELECTFILE, wxT("Select File To Generate Torrent For"), wxPoint(0,48), wxSize(248,24), 0, wxDefaultValidator, wxT("SelectFile"));

	FileNameToMake = new wxTextCtrl(this, ID_FileNameToMake, wxT(""), wxPoint(0,24), wxSize(504,21), 0, wxDefaultValidator, wxT("FileNameToMake"));

	WxStaticText1 = new wxStaticText(this, ID_WXSTATICTEXT1, wxT("Full path to the file or folder you want to generate torrent(s) for:"), wxPoint(0,8), wxSize(320,16), wxST_NO_AUTORESIZE, wxT("WxStaticText1"));
	////GUI Items Creation End
}

void TorrentBuild_CPPDlg::TorrentBuild_CPPDlgClose(wxCloseEvent& event)
{
    Destroy();
}
 

/*
 * ExitWithoutSaveClick
 */
void TorrentBuild_CPPDlg::ExitWithoutSaveClick(wxCommandEvent& event)
{
     exit(0);
}

/*
 * ExitWithSaveClick
 */
void TorrentBuild_CPPDlg::ExitWithSaveClick(wxCommandEvent& event)
{
	SaveSettingsClick(event);
	ExitWithoutSaveClick(event);
}

/*
 * SelectFileClick
 */
void TorrentBuild_CPPDlg::SelectFileClick(wxCommandEvent& event)
{
	BrowseForFile->ShowModal();
	FileNameToMake->SetValue(BrowseForFile->GetPath());
}

/*
 * SelectFolderClick
 */
void TorrentBuild_CPPDlg::SelectFolderClick(wxCommandEvent& event)
{
	BrowseForFolder->ShowModal();
	FileNameToMake->SetValue(BrowseForFolder->GetPath());
}

/*
 * SaveSettingsClick
 */
void TorrentBuild_CPPDlg::SaveSettingsClick(wxCommandEvent& event)
{
	CAtom *pConfigIn = GetConfig();
	CAtomDicti *pConfiguration = new CAtomDicti();
	if( pConfigIn && pConfigIn->isDicti() )
	    pConfiguration = (CAtomDicti *)pConfigIn;
	pConfiguration->setItem( "tracker", new CAtomString(AnnounceURL->GetValue().ToAscii() ) );
	pConfiguration->setItem( "comment", new CAtomString(TorrentComment->GetValue().ToAscii() ) );
	pConfiguration->setItem( "sha1", new CAtomLong(MakeSHA1->GetValue() ) );
	pConfiguration->setItem( "md5", new CAtomLong(MakeMD5->GetValue() ) );
	pConfiguration->setItem( "ed2k", new CAtomLong(MakeED2K->GetValue() ) );
	pConfiguration->setItem( "tiger", new CAtomLong( MakeTiger->GetValue() ) );
	pConfiguration->setItem( "crc32", new CAtomLong( MakeCRC32->GetValue() ) );
	pConfiguration->setItem( "externals", new CAtomLong( MakeExternals->GetValue() ));
	pConfiguration->setItem( "autopiece", new CAtomLong( AutomaticPieceSize->GetValue() ) );
	pConfiguration->setItem( "piecesize", new CAtomLong( UTIL_StringTo64(PieceSize->GetValue() ) ) );
	UTIL_MakeFile( "tgen.configure", Encode( pConfiguration ) );
}

void TorrentBuild_CPPDlg::LoadConfigValues()
{
     CAtom *pConfigValue = GetConfig();
     if( pConfigValue && pConfigValue->isDicti() )
     {
         CAtom *pAnnounce = ((CAtomDicti *)pConfigValue)->getItem("tracker");
         if( pAnnounce && ((CAtomString *)pAnnounce)->getValue() != string() )
             AnnounceURL->SetValue( ((CAtomString *)pAnnounce)->getValue() );
             
         CAtom *pComment = ((CAtomDicti *)pConfigValue)->getItem("comment");
         if( pComment && ((CAtomString *)pComment)->getValue() != string() )
             TorrentComment->SetValue( ((CAtomString *)pComment)->getValue() );

         CAtom *pSHA1 = ((CAtomDicti *)pConfigValue)->getItem("sha1");
         CAtom *pMD5 = ((CAtomDicti *)pConfigValue)->getItem("md5");
         CAtom *pED2K = ((CAtomDicti *)pConfigValue)->getItem("ed2k");
         CAtom *pTTH = ((CAtomDicti *)pConfigValue)->getItem("tiger");
         CAtom *pCRC32 = ((CAtomDicti *)pConfigValue)->getItem("crc");
         CAtom *pExternals = ((CAtomDicti *)pConfigValue)->getItem("externals");
         CAtom *pAutoPiece = ((CAtomDicti *)pConfigValue)->getItem("autopiece");
         CAtom *pPieceSize = ((CAtomDicti *)pConfigValue)->getItem("piecesize");
         if( pSHA1 && pSHA1->isLong() && ((CAtomLong *)pSHA1)->getValue() != 0 ) MakeSHA1->SetValue( true );
         if( pMD5 && pMD5->isLong() && ((CAtomLong *)pMD5)->getValue() != 0 ) MakeMD5->SetValue( true );
         if( pED2K && pED2K->isLong() && ((CAtomLong *)pED2K)->getValue() != 0 ) MakeED2K->SetValue( true );
         if( pTTH && pTTH->isLong() && ((CAtomLong *)pTTH)->getValue() != 0 ) MakeTiger->SetValue( true );
         if( pCRC32 && pCRC32->isLong() && ((CAtomLong *)pCRC32)->getValue() != 0 ) MakeCRC32->SetValue( true );
         if( pPieceSize && pPieceSize->isLong() ) PieceSize->SetValue( UTIL_LongToString(((CAtomLong *)pPieceSize)->getValue()) );
         if( pExternals && pExternals->isLong() && ((CAtomLong *)pExternals)->getValue() != 0 ) MakeExternals->SetValue( true );
         if( pAutoPiece && pAutoPiece->isLong() && ((CAtomLong *)pAutoPiece)->getValue() != 0 ) AutomaticPieceSize->SetValue( true );
     }     
}

/*
 * AutomaticPieceSizeClick
 */
void TorrentBuild_CPPDlg::AutomaticPieceSizeClick(wxCommandEvent& event)
{
    if( AutomaticPieceSize->GetValue() == true )
        PieceSize->Enable(false);
    else
        PieceSize->Enable(true);
}

/*
 * PieceSizeUpdated
 */
void TorrentBuild_CPPDlg::PieceSizeUpdated(wxCommandEvent& event )
{

}

/*
 * PieceSizeUpdateUI
 */
void TorrentBuild_CPPDlg::PieceSizeUpdateUI(wxUpdateUIEvent& event)
{
}

/*
 * PieceSizeSelected
 */
void TorrentBuild_CPPDlg::PieceSizeSelected(wxCommandEvent& event )
{
}

/*
 * BuildTorrentNowClick
 */
void TorrentBuild_CPPDlg::BuildTorrentNowClick(wxCommandEvent& event)
{
    int pieceSizeToUse;
        
	if( UTIL_CheckFile( FileNameToMake->GetValue() ) );
	{
        if( AutomaticPieceSize->GetValue() == true )
            pieceSizeToUse = GetAutoPieceSize( FileSize( FileNameToMake->GetValue() ) );
        else
            pieceSizeToUse = UTIL_StringTo64( PieceSize->GetValue().ToAscii() );
            
        int OptionalHashes = 0;
        if( MakeSHA1->GetValue() == true ) OptionalHashes++;
//        if( MakeMD5->GetValue() == true ) OptionalHashes++;
        if( MakeCRC32->GetValue() == true ) OptionalHashes++;
//        if( MakeED2K->GetValue() == true ) OptionalHashes++;
//        if( MakeTiger->GetValue() == true ) OptionalHashes++;
        
        OptionalHashProgress->SetRange( OptionalHashes );

	    MakeTorrentFromFile( string( FileNameToMake->GetValue() ), pieceSizeToUse, AnnounceURL->GetValue().ToAscii(),
        NULL, TorrentComment->GetValue().ToAscii(), PrivateTorrent->GetValue(), MakeSHA1->GetValue(), MakeCRC32->GetValue(),
        MakeMD5->GetValue(), MakeED2K->GetValue(), MakeTiger->GetValue(), MakeExternals->GetValue() );
    }
}

