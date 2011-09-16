 /* xportscan.cpp

   Copyright (C) 2003 Miguel Morales
   All Rights Reserved.

   xportscan is free software; you can redistribute it
   and/or modify it under the terms of the GNU General Public License as
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
#include "xportscan.h"
#ifndef __WXMSW__
#include "scan_engine.h"
#else
#include "win_scan_engine.cpp"
#endif
#include "panel_wdr.cpp"
void iterate_ports();
class MyFrame *frame;
struct options opt;
void FoundOpenPort(int, int index = 0);
BEGIN_EVENT_TABLE(MyFrame, wxFrame)
  EVT_BUTTON(ID_START, MyFrame::Start)
  EVT_BUTTON(ID_STOP, MyFrame::Stop)
  EVT_MENU(411, MyFrame::Quit)
  EVT_MENU(412, MyFrame::Log)
  EVT_MENU(413, MyFrame::SetPath)

  EVT_MENU(HELP, MyFrame::Help)
  EVT_MENU(ABOUT, MyFrame::About)
  EVT_MENU(LICENSE, MyFrame::License)

  EVT_CHOICE(PORT_CHOICE, MyFrame::OnPortChoiceSelect)
  EVT_CHECKBOX(CHECK_THREADS, MyFrame::OnCheckThreads)
  EVT_LIST_ITEM_ACTIVATED(PORT_LIST, MyFrame::OnListActivate)
  END_EVENT_TABLE()
  IMPLEMENT_APP(MyApp)
  bool MyApp::OnInit()
{
#ifdef __WXMSW__
  frame = new MyFrame( "XPortScan", wxPoint(50,50), wxSize(450,440));
#else
  frame = new MyFrame( "XPortScan", wxPoint(50,50), wxSize(450,440));
#endif
  frame->Show( TRUE );
  SetTopWindow( frame );
#ifdef __WXMSW__
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0)
    {
    }
#endif
/*See if we can find portlist.txt*/
wxConfig config("xportscan");
if (!config.Read("path", &opt.path))
opt.path = ".";
if (!wxFileExists(opt.path + "/portlist.txt"))
	{
  wxMessageBox("Application Path not valid, please select path. \n(Must containt portlist.txt and helpfiles)\nIt will be stored in configuration)", "XPortScan Error", wxOK|wxICON_ERROR);
  frame->SetPath();
	}

/*initialize help files*/
(frame->help).Initialize(opt.path + "/helpfiles/help");
return TRUE;

}

void MyFrame::SetPath()
{
wxConfig config("xportscan");
  wxDirDialog filedialog(frame, "Select Application Path",wxGetCwd());
  if (filedialog.ShowModal() == wxID_CANCEL) return;
	config.Write("path", filedialog.GetPath());
	opt.path = filedialog.GetPath();
if (!wxFileExists(opt.path + "/portlist.txt"))
	{
  wxMessageBox("Warning:\nportlist.txt not found in specified path.", "XPortScan Error", wxOK|wxICON_WARNING);
  }
}

int MyApp::OnExit()
{
#ifdef __WXMSW__
  WSACleanup();
#endif
STOP_SNIFFER = TRUE;
  return 0;
}
void *SnifferThread::Entry()
{
set_sniffer(type);
return NULL;
}

MyFrame::MyFrame(const wxString& title, const wxPoint& pos, const wxSize& size, long style)
  : wxFrame((wxFrame *)NULL, -1, title, pos, size, style)
{
  wxMenuBar *menuBar = new wxMenuBar;
  wxMenu *menuFile = new wxMenu;
  menuFile->Append(412, "Log to File", "Log scan results to file.");
  menuFile->Append(413, "Set Application Path", "Change the path of the portlist and help files");
  menuFile->Append(411, "Quit", "Exit XPortScan");

  wxMenu *menuHelp = new wxMenu;

  menuHelp->Append(HELP, "XPortScan Help", "Show XPortScan Help");
	menuHelp->Append(ABOUT, "About", "About XPortScan");
	menuHelp->Append(LICENSE, "License", "Show License");
  menuBar->Append(menuFile, "&File");
  menuBar->Append(menuHelp, "&Help");
  SetMenuBar( menuBar );
  wxPanel *panel = new wxPanel(this);
  top_panel(panel, TRUE, TRUE);
  LoadControls();
  port_choice->SetSelection(0);
  scan_choice->SetSelection(0);
  port_list->InsertColumn(0, "Port");
  port_list->InsertColumn(1, "Service", wxLIST_FORMAT_LEFT, 300);
  text_addr->SetFocus();
  text_addr->SetSelection(-1, -1);
  SetIcon(wxICON(MyIcon));


  CreateStatusBar();
}

void MyFrame::Log()
{
  wxString service;
  struct servent *srvc;
	wxString to_save;
wxFile file;
wxFileDialog filedialog(this,"Save As...",wxGetCwd(),text_addr->GetValue() + ".txt","All Files (**)|**",wxSAVE|wxOVERWRITE_PROMPT ,wxDefaultPosition);
 if (filedialog.ShowModal() == wxID_CANCEL)
 {
 return;
 }
#ifdef __WXMSW__
#define end_line "\r\n"
#else
#define end_line "\n"
#endif
to_save = wxString("XPortScan Log").Append(end_line);
to_save += "Date: " + wxNow()+ end_line;
to_save += "Host: " + opt.host_addr + end_line;
to_save += "Scan Type: ";
switch (opt.scan_type)
{
case TCP_SCAN:
to_save += "TCP Connect()";
break;
case SYN_SCAN:
to_save += "SYN";
break;
case UDP_SCAN:
to_save += "UDP";
break;
case FIN_SCAN:
to_save += "FIN";
break;
case XMAS_SCAN:
to_save += "XMAS";
break;
case NULL_SCAN:
to_save += "NULL";
break;
}
to_save += end_line;
to_save += end_line;
for (int x = 0; x < port_list->GetItemCount(); x++)
	{
to_save += "Port: ";	
to_save += port_list->GetItemText(x);
to_save += "  Service: ";
  if (opt.scan_type == UDP_SCAN)
    srvc = getservbyport(htons(atoi(port_list->GetItemText(x))), "udp");
  else
    srvc = getservbyport(htons(atoi(port_list->GetItemText(x))), "tcp");
  service = (srvc == NULL) ? "UNKNOWN" : srvc->s_name;
if (!opt.custom_port)
for (unsigned int y = 0; y < (frame->port_array).GetCount(); y++)
	{
	if (frame->port_array[y] == port_list->GetItemText(x))
      {
			service += " / ";
      service += frame->service_array[y];
			}
	}/*end of for()*/
to_save += service;
to_save += end_line;
}/*end of for()*/

file.Open((filedialog.GetPath()).c_str(),wxFile::write);
if (file.Write(to_save))
SetStatusText("Saved as: " + filedialog.GetPath());
else
SetStatusText("Error: " + filedialog.GetPath());
 file.Close();
}/*end of log() function*/

void MyFrame::Start()
{
wxThread *sniff = NULL;
PAUSE = FALSE;
STOP_SNIFFER = TRUE;
wxSleep(1);
STOP_SNIFFER = FALSE;
n_threads = 0;
  scanned_ports = 0;
  port_array.Clear();
  service_array.Clear();
  port_list->DeleteAllItems();
  SetOpt();
	if (opt.scan_type != TCP_SCAN)
	{
/*Not yet supported*/
#ifdef __WXMSW__
if (opt.scan_type != TCP_SCAN)
{
wxMessageBox("Only Connect scan method is supported for now", "XPortScan Error", wxOK|wxICON_ERROR);
return;}
#else
if (opt.scan_type == UDP_SCAN)
{
wxMessageBox("This scan type is not currently supported.", "XPortScan Error", wxOK|wxICON_ERROR);
return;}
#endif



#ifndef __WXMSW__
		if (getuid() != 0)
			{
			wxMessageBox("You must be root to use this scan type", "XPortScan Error", wxOK | wxICON_ERROR);
			return;
			}
#endif			
		get_ip();
/******Set Sniffer*/
switch (opt.scan_type)
{
case SYN_SCAN:
sniff = new SnifferThread(SYN);
break;
case FIN_SCAN:
sniff = new SnifferThread(FIN);
case NULL_SCAN:
sniff = new SnifferThread(NULL_S);
break;
case XMAS_SCAN:
sniff = new SnifferThread(XMAS);
break;
case UDP_SCAN:
sniff = new SnifferThread(UDP);
default:
/*This shouldn't happen*/
break;
}
if ( sniff->Create() != wxTHREAD_NO_ERROR )
 {
 wxMessageBox("Could not create sniffer thread", "XportScan Error", wxOK | wxICON_ERROR);
return;
 }
sniff->Run();

/*****End Set Sniffer*/
	}
  if((host = gethostbyname((opt.host_addr).c_str())) == NULL)
    {
      wxMessageBox("Couldn't resolve: " + opt.host_addr);
      return;
    }

  if (opt.custom_port)
    {
      for (int x = opt.start_port; x <= opt.end_port; x++) 
	port_array.Add(wxString::Format("%d", x));
    }
 else
    {	    
      if (opt.scan_type == UDP_SCAN)	
	{
	  if (!LoadPortsFromFile(opt.path + "/portlist.txt", "udp"))
	    {
	      return;
	    }
	}
      else 
	{
	  if (!LoadPortsFromFile(opt.path + "/portlist.txt", "tcp"))
	    { 
	      //        return;   
	    }
	}
    }

  //Set time-out:
  timeout.tv_sec = opt.sec;
  timeout.tv_usec = opt.usec;
  SetStatusText("Scanning...");
//Start timer...
wxStopWatch tm;
  if (opt.disable_threads)
    DoNormalLoop();
  else
    DoThreadLoop();
  //Do a little loop to check if all port have been scanned
  //This will work for both threads and normal loop
  int total_ports;
  if (opt.custom_port)
    total_ports = (opt.end_port - opt.start_port) + 1;
  else
    total_ports = port_array.GetCount();

  while (scanned_ports < total_ports)
    {
      if (PAUSE) {break;}
      wxYield();
    }
if (opt.scan_type == FIN_SCAN ||opt.scan_type == XMAS_SCAN ||opt.scan_type == NULL_SCAN)
	{
if (PAUSE){
//TODO: iterate through ports which raw packet has been sent*/
  SetStatusText("STOPPED");
	return;  }
	}

if (opt.scan_type != TCP_SCAN && opt.scan_type != SYN_SCAN && opt.scan_type != UDP_SCAN)
{
/*TODO: Only sleep according to the number of ports scanned*/
printf("sleeping to wait for packets\n");
wxSleep(2);
printf("iterating\n");
iterate_ports();
}

tm.Pause();
SetStatusText(wxString::Format("%d port(s) scanned in %.2f seconds.", scanned_ports, (float)tm.Time()/1000));
/*
STOP_SNIFFER = TRUE;
wxSleep(1);
STOP_SNIFFER = FALSE;
*/
}

void MyFrame::DoThreadLoop()
{
  //Loop through each port, using threads
  for (unsigned int x = 0; x < port_array.GetCount(); x++)
    {
      wxYield();
      if (PAUSE) break;
      //Check is max threads has been reached
      if ((unsigned)opt.max_threads <= frame->n_threads)
	{
      x--;
	  continue;
	}
      
      wxThread *thread = new ScanThread(atoi(port_array[x]), x);
      if ( thread->Create() != wxTHREAD_NO_ERROR )
	{
	  wxMessageBox("No Resources left, try decreasing the number of threads", "XPortScan Error", wxOK | wxICON_ERROR);
	  return;
	}
    /*
      unsigned int tmp = thread_array.GetCount();
      thread_array.Insert(thread, tmp);
      thread_array[tmp]->Run();
*/
          thread->Run();
//if (opt.host_addr != "127.0.0.1" && opt.host_addr != "localhost.localdomain")
if (opt.scan_type != TCP_SCAN)
wxUsleep(opt.packet_delay);

	  }
}

void MyFrame::DoNormalLoop()
{
  for (unsigned int x = 0; x < port_array.GetCount(); x++)
    {
      if (opt.host_addr != "127.0.0.1" && opt.host_addr != "localhost.localdomain")
if (opt.scan_type != TCP_SCAN && opt.scan_type != SYN_SCAN)
	wxYield();
      if (PAUSE) break;
      switch (opt.scan_type)
	{
	case UDP_SCAN:
	  if (udp_scan(atoi(port_array[x]))) FoundOpenPort(atoi(port_array[x]), x);
	  break;
	case SYN_SCAN:
	  if (raw_scan(atoi(port_array[x]), SYN)) FoundOpenPort(atoi(port_array[x]), x);
//      if (opt.host_addr != "127.0.0.1" && opt.host_addr != "localhost.localdomain")
		wxUsleep(opt.packet_delay);
	  break;
	case FIN_SCAN:
	  if (raw_scan(atoi(port_array[x]), FIN)) FoundOpenPort(atoi(port_array[x]), x);
		wxUsleep(opt.packet_delay);
	  break;
	case XMAS_SCAN:
	  if (raw_scan(atoi(port_array[x]), XMAS)) FoundOpenPort(atoi(port_array[x]), x);
				wxUsleep(opt.packet_delay);
	  break;
	case NULL_SCAN:
	  if (raw_scan(atoi(port_array[x]), NULL_S)) FoundOpenPort(atoi(port_array[x]), x);
		wxUsleep(opt.packet_delay);
	  break;
	default:
	  if (tcp_scan(atoi(port_array[x]))) FoundOpenPort(atoi(port_array[x]), x);
	  break;
	}
      scanned_ports++;
    }
}

void *ScanThread::Entry()
{
printf("port: %d\n", port);
frame->n_threads++;
  switch (opt.scan_type)
    {
    case UDP_SCAN:
      if (udp_scan(port)) FoundOpenPort(port, index);
      break;
    case SYN_SCAN:
      if (raw_scan(port, SYN)) FoundOpenPort(port, index);
        break;
    case FIN_SCAN:
      if (raw_scan(port, FIN)) FoundOpenPort(port, index);
      break;
    case XMAS_SCAN:
      if (raw_scan(port, XMAS)) FoundOpenPort(port, index);
      break;
    case NULL_SCAN:
      if (raw_scan(port, NULL_S)) FoundOpenPort(port, index);
      break;
    default:
      if (tcp_scan(port)) FoundOpenPort(port, index);
      break;
    }

  return NULL;
}

void ScanThread::OnExit()
{
//  (frame->thread_array).Remove(this);
frame->n_threads--;
  frame->scanned_ports++;
}

void MyFrame::Stop()
{
  PAUSE = TRUE;
}

void MyFrame::Quit()
{
  Close(TRUE);
}

void MyFrame::LoadControls()
{
  port_list = (wxListCtrl *)FindWindowById(PORT_LIST, this);
  text_addr = (wxTextCtrl *)FindWindowById(TEXT_HOST, this);
  s_port = (wxTextCtrl *)FindWindowById(START_PORT, this);
  e_port = (wxTextCtrl *)FindWindowById(END_PORT, this);
  scan_choice = (wxChoice *)FindWindowById(SCAN_CHOICE, this);
  port_choice = (wxChoice *)FindWindowById(PORT_CHOICE, this);
  sec_text = (wxSpinCtrl *)FindWindowById(SEC_TEXT, this);
  usec_text = (wxSpinCtrl *)FindWindowById(USEC_TEXT, this);
	delay_text = (wxSpinCtrl *)FindWindowById(DELAY_TEXT, this);
  thread_text  = (wxSpinCtrl *)FindWindowById(THREAD_TEXT, this);
  thread_disable = (wxCheckBox *)FindWindowById(CHECK_THREADS, this);
}

void MyFrame::SetOpt()
{
  if (port_choice->GetStringSelection() == "Custom") opt.custom_port = TRUE; else opt.custom_port = FALSE;
  if (opt.custom_port) 
    {
      opt.start_port = atoi(s_port->GetValue());
      opt.end_port = atoi(e_port->GetValue());
    }  
  switch(scan_choice->GetSelection())
    {
		case 5:
    opt.scan_type = NULL_SCAN;
		break;
		case 4:
    opt.scan_type = XMAS_SCAN;
		break;
		case 3:
    opt.scan_type = FIN_SCAN;
		break;
    case 2:
      opt.scan_type = SYN_SCAN;
      break;
    case 1:
      opt.scan_type = UDP_SCAN;
      break;
  default:
      opt.scan_type = TCP_SCAN;
      break;
    }
  switch (port_choice->GetSelection())
    {
    case 1:
      opt.custom_port = TRUE;
      break;
    default:
      opt.custom_port = FALSE;
      break;
    }
  if (thread_disable->GetValue())
    opt.disable_threads = TRUE;
  else
    {
      opt.max_threads = thread_text->GetValue();
      opt.disable_threads = FALSE;
    }
  opt.sec = sec_text->GetValue();
  opt.usec = usec_text->GetValue();
	opt.packet_delay = 	delay_text->GetValue();
  opt.host_addr = text_addr->GetValue();
  //If scanning local network disable threads...
#ifndef __WXMSW__
  //if (opt.host_addr == "127.0.0.1" || opt.host_addr == "localhost.localdomain")
    //opt.disable_threads = TRUE;
#endif
}

void MyFrame::OnPortChoiceSelect()
{
  if (port_choice->GetStringSelection() == "Custom")
    {
      s_port->Enable(TRUE);
      e_port->Enable(TRUE);
    }
  else
    {
      s_port->Disable();
      e_port->Disable();
    }
}

void MyFrame::OnCheckThreads()
{
  if (thread_disable->GetValue())
    {
      thread_text->Disable();
    }
  else
    {
      thread_text->Enable(TRUE);
    }
}

void MyFrame::OnListActivate()
{
/*This happens when an item on the port list is double clicked*/
/*Plan on adding something here*/
}


bool MyFrame::LoadPortsFromFile(wxString filename, wxString serv)
{
  wxTextFile file;
  wxString temp;
  wxString temp2;
  int tempx;
wxBusyInfo msg("Loading port list...");
//First add ports 1-1024
for (tempx = 0; tempx <= 1024; tempx++) 
    {
    port_array.Add(wxString::Format("%d", tempx));
   service_array.Add("");
    }
    
  if (!file.Open(filename))
    {
      //wxMessageBox("Error Opening: " + filename, "XPortScan Error", wxOK|wxICON_ERROR);
      return FALSE;
    }
  file.GetFirstLine();
  while (!file.Eof())
    {
      temp = file.GetNextLine();
      if (temp == "") continue;
      //Ignore lines that start with '#'
      if (temp.StartsWith("#")) continue;
      temp2 = temp;
      temp = getsub(temp.c_str(), " ", wxString("/" + serv).c_str()).c_str();
      if (temp == "-1" || temp == "-2") continue;
      temp.Trim(FALSE);

  if (atoi(temp) <= 1024)
      {
      if (temp2.Contains(serv))
    	{
	  temp2 = temp2.BeforeFirst(' ');
   service_array[atoi(temp)] = temp2;
	  
	    }
       continue;
      }
    
      port_array.Add(temp);
      if (temp2.Contains(serv))
	{
	  temp2 = temp2.BeforeFirst(' ');
	  service_array.Add(temp2);
	}
    }
  file.Close();
  //for (unsigned int x = 0; x < port_array.GetCount(); x++)
  //cout << port_array[x] << endl;
printf("port_array: %d\n", port_array.GetCount());
frame->loaded_port_list = TRUE;
  return TRUE;
}

wxString getsub (const char* FULL, const char sub1[], const char sub2[]) {
  std::string full;
  full.append(FULL);
  int length = full.length();
  unsigned int loc = full.find(sub1, 0 );
  if( loc != std::string::npos )
    {
      int indexlength = strlen(sub1);
      loc = loc + indexlength;

      std::string str2 = full.substr(loc, length);

      unsigned int loc2 = str2.find(sub2, 0);
      if( loc2 != std::string::npos ){
	std::string substring = str2.substr(0, loc2);

	return wxString(substring.c_str());
      }
      else{
	return "-2";
      }
    }
  else{
    return "-1";
  }
}

void FoundOpenPort(int port, int index)
{
  wxString service;
  struct servent *srvc;
  if (opt.scan_type == UDP_SCAN)
    srvc = getservbyport(htons(port), "udp");
  else
    srvc = getservbyport(htons(port), "tcp");

  service = (srvc == NULL) ? "UNKNOWN" : srvc->s_name;

  if (!opt.custom_port)
    {
if (port <= 1024)
    {
    if (!(frame->service_array[port]).IsEmpty())
        {
        service += " / ";
        service += frame->service_array[port];
        }
    }
else
        {
        service += " / ";
        service += frame->service_array[index];
        }
    }

  (frame->port_list)->InsertItem(0, wxString::Format("%d", port));
  (frame->port_list)->SetItem(0, 1, service);
}

void opened_raw_port(int port)
{
wxString service;
struct servent *srvc;
srvc = getservbyport(htons(port), "tcp");
service = (srvc == NULL) ? "UNKNOWN" : srvc->s_name;

for (int x = 0; x < (frame->port_list)->GetItemCount(); x++)
if ((frame->port_list)->GetItemText(x) == wxString::Format("%d", port))
return;

  (frame->port_list)->InsertItem(0, wxString::Format("%d", port));
  (frame->port_list)->SetItem(0, 1, service);
}

void closed_raw_port(int port)
{
/*iterate through the port array*/
for (unsigned int x = 0; x < (frame->port_array).GetCount(); x++)
	{
	if (frame->port_array[x] == wxString::Format("%d", port))
	frame->port_array[x] = "closed";
	}
//printf("%d closed\n", port);
}

void iterate_ports()
{
for (unsigned int x = 0; x < (frame->port_array).GetCount(); x++)
	if (frame->port_array[x] != "closed" && (frame->port_array[x]).IsNumber())
		{
		FoundOpenPort(atoi(frame->port_array[x]), x);
		frame->port_array[x] = "closed";
		}
}

/*Help Menu Functions*/
void MyFrame::Help()
{
help.DisplayContents();
}

void MyFrame::About()
{
help.DisplaySection("About");
}
void MyFrame::License()
{
help.DisplaySection("License");
}

