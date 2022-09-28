#ifndef IEC104_CONFIG_H
#define IEC104_CONFIG_H

#include "logger.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include <map>
#include <vector>

#include "iec104_datapoint.hpp"
#include <lib60870/cs104_slave.h>

using namespace std;

class IEC104Config
{
public:
    IEC104Config();
    IEC104Config(const string& protocolConfig, const string& exchangeConfig);
    ~IEC104Config();

    void importProtocolConfig(const string& protocolConfig);
    void importExchangeConfig(const string& exchangeConfig);

    std::map<int, std::map<int, IEC104DataPoint*>>* getExchangeDefinitions() {return m_exchangeDefinitions;};

    std::vector<CS104_RedundancyGroup> getRedGroups() {return m_configuredRedundancyGroups;};

    int TcpPort();
    bool bindOnIp() {return m_bindOnIp;};
    int K() {return m_k;};
    int W() {return m_w;};
    int T0() {return m_t0;};
    int T1() {return m_t1;};
    int T2() {return m_t2;};
    int T3() {return m_t3;};
    int UseTLS() {return m_useTls;};
    const char* GetLocalIP() {return m_ip.c_str();};

    int CaSize() {return m_caSize;};
    int IOASize() {return m_ioaSize;};
    int AsduSize() {return m_asduSize;};

    int AsduQueueSize() {return m_asduQueueSize;};

    bool TimeSync() {return m_timeSync;};

    bool IsOriginatorAllowed(int oa);

    bool AllowCmdWithTime();
    bool AllowCmdWithoutTime();

    int CmdRecvTimeout() {return m_cmdRecvTimeout;};
    int CmdExecTimeout() {return m_cmdExecTimeout;};

    string& ControlTarget() {return m_controlTarget;};

private:

    static bool isValidIPAddress(const string& addrStr);

    void deleteExchangeDefinitions();
    
    bool m_protocolConfigComplete;
    bool m_exchangeConfigComplete;

    bool m_useTls = false;
    int m_tcpPort = -1; /* use default port */
    bool m_bindOnIp = false;
    int m_k = 12;
    int m_w = 8;
    int m_t0 = 30;
    int m_t1 = 15;
    int m_t2 = 10;
    int m_t3 = 20;

    int m_caSize = 2;
    int m_ioaSize = 3;
    int m_asduSize = 0;

    int m_asduQueueSize = 100;

    bool m_timeSync = false;
    bool m_filterOriginators = false;

    int m_allowedCommands = 1; /* 0 - only without timestamp, 1 - only with timestamp, 2 - both */

    int m_cmdRecvTimeout = 0;
    int m_cmdExecTimeout = 20;

    string m_ip;

    string m_controlTarget = "";

    std::vector<CS104_RedundancyGroup> m_configuredRedundancyGroups;

    std::map<int, std::map<int, IEC104DataPoint*>>* m_exchangeDefinitions = nullptr;
    std::map<int, int> m_allowedOriginators;
};

#endif /* IEC104_CONFIG_H */