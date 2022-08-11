#ifndef IEC104_CONFIG_H
#define IEC104_CONFIG_H

#include "logger.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include <map>

#include "iec104_datapoint.hpp"

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
    int getTcpPort();

private:
    
    bool m_protocolConfigComplete;
    bool m_exchangeConfigComplete;

    int m_tcpPort = -1;

    std::map<int, std::map<int, IEC104DataPoint*>>* m_exchangeDefinitions = nullptr;

};

#endif /* IEC104_CONFIG_H */