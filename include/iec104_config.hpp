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

    std::map<int, std::map<int, IEC104DataPoint*>>* getExchangeDefinitions();

    std::vector<CS104_RedundancyGroup> getRedGroups();

    int getTcpPort();

private:
    
    bool m_protocolConfigComplete;
    bool m_exchangeConfigComplete;

    int m_tcpPort = -1;

    std::vector<CS104_RedundancyGroup> m_configuredRedundancyGroups;

    std::map<int, std::map<int, IEC104DataPoint*>>* m_exchangeDefinitions = nullptr;

};

#endif /* IEC104_CONFIG_H */