  /* xportscan.h

   Copyright (C) 2003 Miguel Morales
   All Rights Reserved.

   xportscan is free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Miguel Morales
   <mrx@netlane.com>
 */
#include "wx/wxprec.h"
#ifdef __BORLANDC__
#pragma hdrstop
#endif
#ifndef WX_PRECOMP
#include <wx/wx.h>
#endif
#if defined(__WXGTK__) || defined(__WXMOTIF__) || defined(__WXMAC__) || defined(__WXMGL__) || defined(__WXX11__)
#include "icon.xpm"
#endif
#if !wxUSE_THREADS
#error "This sample requires thread support!"
#endif
#include <wx/thread.h>
#include <wx/dynarray.h>
#include <wx/listctrl.h>
#include <wx/spinctrl.h>
#include <wx/textfile.h>
#include <wx/timer.h>
#include <wx/config.h>
#include <wx/busyinfo.h>

#include <wx/fs_zip.h>
#include <wx/html/helpctrl.h>
#include <string>

void SetListener();
wxString getsub (const char * FULL, const char sub1[], const char sub2[]);
WX_DEFINE_ARRAY(wxThread *, wxArrayThread);
enum
{
  TCP_SCAN = 0,
  UDP_SCAN,
  SYN_SCAN,
	FIN_SCAN,
	XMAS_SCAN,
	NULL_SCAN,
	HELP,
	ABOUT,
	LICENSE,
};

class MyApp : public wxApp
{
 public:
  virtual bool OnInit();
  int OnExit();
};

class MyFrame : public wxFrame
{
 public:
  MyFrame(const wxString& title, const wxPoint& pos, const wxSize& size,
	  long style = wxDEFAULT_FRAME_STYLE);
  bool PAUSE;
  bool loaded_port_list;
  wxListCtrl *port_list;
  wxTextCtrl *text_addr;
  wxTextCtrl *s_port;
  wxTextCtrl *e_port;
  wxChoice *scan_choice;
  wxChoice *port_choice;
  wxSpinCtrl *sec_text;
  wxSpinCtrl *usec_text;
  wxSpinCtrl *delay_text;
  wxSpinCtrl *thread_text;
  wxCheckBox *thread_disable;
  unsigned int array_index;
  wxArrayString port_array; //This is the array that stores port numbers
  wxArrayString service_array; //This array stores service for ports
  wxArrayThread thread_array; //This is where we store the threads
  
unsigned int n_threads; //Number of threads
  int scanned_ports; //The ports scanned
  wxHtmlHelpController help;
  bool LoadPortsFromFile(wxString, wxString serv = "tcp");
  void DoThreadLoop();
  void DoNormalLoop();
  void Start();
  void Stop();
  void Quit();
  void LoadControls();
  void SetOpt();
  void OnPortChoiceSelect();
  void OnCheckThreads();
  void OnListActivate();
	void Log();
	void SetPath();
void MyFrame::Help();
void MyFrame::License();
void MyFrame::About();
 private:
  DECLARE_EVENT_TABLE()
    };


    struct options
    {
      bool custom_port;
      int start_port;
      int end_port;
      int scan_type;
      int max_threads;
      bool disable_threads;
      int sec;
      int usec;
			int packet_delay;
			wxString path;
      wxString host_addr;
    };

class ScanThread : public wxThread
{
 public:
  ScanThread(int, int);
  int port;
  int index;
  virtual void *Entry();
  virtual void OnExit();
};

ScanThread::ScanThread(int temp, int temp2)
{
  port = temp;
  index = temp2;
}

class SnifferThread: public wxThread
{
public:
int type;
SnifferThread(int);
virtual void *Entry();
};

SnifferThread::SnifferThread(int tmp)
{
type = tmp;
}


