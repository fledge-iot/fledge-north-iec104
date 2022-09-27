#include <arpa/inet.h>

#include "iec104_config.hpp"

using namespace rapidjson;

#define JSON_EXCHANGED_DATA "exchanged_data"
#define JSON_DATAPOINTS "datapoints"
#define JSON_PROTOCOLS "protocols"
#define JSON_LABEL "label"

#define PROTOCOL_IEC104 "iec104"
#define JSON_PROT_NAME "name"
#define JSON_PROT_ADDR "address"
#define JSON_PROT_TYPEID "typeid"

IEC104Config::IEC104Config()
{
    m_exchangeConfigComplete = false;
    m_protocolConfigComplete = false;
}

IEC104Config::IEC104Config(const string& protocolConfig, const string& exchangeConfig)
{
    importProtocolConfig(protocolConfig);
    importExchangeConfig(exchangeConfig);
}

void
IEC104Config::deleteExchangeDefinitions()
{
    if (m_exchangeDefinitions != nullptr) {
        for (auto const& exchangeDefintions : *m_exchangeDefinitions) {
            for (auto const& dpPair : exchangeDefintions.second) {
                IEC104DataPoint* dp = dpPair.second;

                delete dp;
            }
        }

        delete m_exchangeDefinitions;

        m_exchangeDefinitions = nullptr;
    }
}

IEC104Config::~IEC104Config()
{
    deleteExchangeDefinitions();
}

bool
IEC104Config::isValidIPAddress(const string& addrStr)
{
    // see https://stackoverflow.com/questions/318236/how-do-you-validate-that-a-string-is-a-valid-ipv4-address-in-c
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, addrStr.c_str(), &(sa.sin_addr));

    return (result == 1);
}

void
IEC104Config::importProtocolConfig(const string& protocolConfig)
{
    m_protocolConfigComplete = false;

    Document document;

    if (document.Parse(const_cast<char*>(protocolConfig.c_str())).HasParseError()) {
        Logger::getLogger()->fatal("Parsing error in protocol configuration");

        printf("Parsing error in protocol configuration\n");

        return;
    }

    if (!document.IsObject()) {
        return;
    }

    if (!document.HasMember("protocol_stack") || !document["protocol_stack"].IsObject()) {
        return;
    }

    const Value& protocolStack = document["protocol_stack"];

    if (!protocolStack.HasMember("transport_layer") || !protocolStack["transport_layer"].IsObject()) {
        Logger::getLogger()->fatal("transport layer configuration is missing");
    
        return;
    }

    if (!protocolStack.HasMember("application_layer") || !protocolStack["application_layer"].IsObject()) {
        Logger::getLogger()->fatal("appplication layer configuration is missing");
    
        return;
    }

    const Value& transportLayer = protocolStack["transport_layer"];
    const Value& applicationLayer = protocolStack["application_layer"];

    if (transportLayer.HasMember("redundancy_groups")) {

        if (transportLayer["redundancy_groups"].IsArray()) {

            const Value& redundancyGroups = transportLayer["redundancy_groups"];

            for (const Value& redGroup : redundancyGroups.GetArray()) {
                
                char* redGroupName = NULL;

                if (redGroup.HasMember("rg_name")) {
                    if (redGroup["rg_name"].IsString()) {
                        string rgName = redGroup["rg_name"].GetString();

                        redGroupName = strdup(rgName.c_str());
                    }
                }

                CS104_RedundancyGroup redundancyGroup = CS104_RedundancyGroup_create(redGroupName);
          
                printf("Adding red group with name: %s\n", redGroupName);

                free(redGroupName);

                if (redGroup.HasMember("connections")) {
                    if (redGroup["connections"].IsArray()) {
                        for (const Value& con : redGroup["connections"].GetArray()) {
                            if (con.HasMember("clt_ip")) {
                                if (con["clt_ip"].IsString()) {
                                    string cltIp = con["clt_ip"].GetString();

                                    if (isValidIPAddress(cltIp)) {
                                        CS104_RedundancyGroup_addAllowedClient(redundancyGroup, cltIp.c_str());

                                        printf("  add to group: %s\n", cltIp.c_str());
                                    }
                                    else {
                                        printf("  %s is not a valid IP address -> ignore\n", cltIp.c_str());
                                        Logger::getLogger()->error("s is not a valid IP address -> ignore", cltIp.c_str());
                                    }

                                }
                            }
                        }
                    }
                }

                m_configuredRedundancyGroups.push_back(redundancyGroup);
            }
        }
        else {
            Logger::getLogger()->fatal("redundancy_groups is not an array -> ignore redundancy groups");
        }
    }

    if (transportLayer.HasMember("port")) {
        if (transportLayer["port"].IsInt()) {
            int tcpPort = transportLayer["port"].GetInt();

            if (tcpPort > 0 && tcpPort < 65536) {
                m_tcpPort = tcpPort;
            }
            else {
                Logger::getLogger()->warn("transport_layer.port value out of range-> using default port");
            }
        }
        else {
            printf("transport_layer.port has invalid type -> using default port\n");
            Logger::getLogger()->warn("transport_layer.port has invalid type -> using default port");
        }
    }

    if (transportLayer.HasMember("k_value")) {
        if (transportLayer["k_value"].IsInt()) {
            int kValue = transportLayer["k_value"].GetInt();

            if (kValue > 0 && kValue < 32768) {
                m_k = kValue;
            }
            else {
                Logger::getLogger()->warn("transport_layer.k_value value out of range-> using default value");
            }
        }
        else {
            printf("transport_layer.k_value has invalid type -> using default value\n");
            Logger::getLogger()->warn("transport_layer.k_value has invalid type -> using default value");
        }
    }

    if (transportLayer.HasMember("w_value")) {
        if (transportLayer["w_value"].IsInt()) {
            int wValue = transportLayer["w_value"].GetInt();

            if (wValue > 0 && wValue < 32768) {
                m_w = wValue;
            }
            else {
                Logger::getLogger()->warn("transport_layer.w_value value out of range-> using default value");
            }
        }
        else {
            printf("transport_layer.w_value has invalid type -> using default value\n");
            Logger::getLogger()->warn("transport_layer.w_value has invalid type -> using default value");
        }
    }

    if (transportLayer.HasMember("t0_timeout")) {
        if (transportLayer["t0_timeout"].IsInt()) {
            int t0Timeout = transportLayer["t0_timeout"].GetInt();

            if (t0Timeout > 0 && t0Timeout < 256) {
                m_t0 = t0Timeout;
            }
            else {
                Logger::getLogger()->warn("transport_layer.t0_timeout value out of range-> using default value");
            }
        }
        else {
            printf("transport_layer.t0_timeout has invalid type -> using default value\n");
            Logger::getLogger()->warn("transport_layer.t0_timeout has invalid type -> using default value");
        }
    }

    if (transportLayer.HasMember("t1_timeout")) {
        if (transportLayer["t1_timeout"].IsInt()) {
            int t1Timeout = transportLayer["t1_timeout"].GetInt();

            if (t1Timeout > 0 && t1Timeout < 256) {
                m_t1 = t1Timeout;
            }
            else {
                Logger::getLogger()->warn("transport_layer.t1_timeout value out of range-> using default value");
            }
        }
        else {
            printf("transport_layer.t1_timeout has invalid type -> using default value\n");
            Logger::getLogger()->warn("transport_layer.t1_timeout has invalid type -> using default value");
        }
    }

    if (transportLayer.HasMember("t2_timeout")) {
        if (transportLayer["t2_timeout"].IsInt()) {
            int t2Timeout = transportLayer["t2_timeout"].GetInt();

            if (t2Timeout > 0 && t2Timeout < 256) {
                m_t2 = t2Timeout;
            }
            else {
                Logger::getLogger()->warn("transport_layer.t2_timeout value out of range-> using default value");
            }
        }
        else {
            printf("transport_layer.t2_timeout has invalid type -> using default value\n");
            Logger::getLogger()->warn("transport_layer.t2_timeout has invalid type -> using default value");
        }
    }

    if (transportLayer.HasMember("t3_timeout")) {
        if (transportLayer["t3_timeout"].IsInt()) {
            int t3Timeout = transportLayer["t3_timeout"].GetInt();

            if (t3Timeout > -1) {
                m_t3 = t3Timeout;
            }
            else {
                Logger::getLogger()->warn("transport_layer.t3_timeout value out of range-> using default value");
            }
        }
        else {
            printf("transport_layer.t3_timeout has invalid type -> using default value\n");
            Logger::getLogger()->warn("transport_layer.t3_timeout has invalid type -> using default value");
        }
    }

    if (transportLayer.HasMember("tls")) {
        if (transportLayer["tls"].IsBool()) {
            m_useTls = transportLayer["tls"].GetBool();
        }
        else {
            printf("transport_layer.tls has invalid type -> not using TLS\n");
            Logger::getLogger()->warn("transport_layer.tls has invalid type -> not using TLS");
        }
    }

    if (transportLayer.HasMember("srv_ip")) {
        if (transportLayer["srv_ip"].IsString()) {

            if (isValidIPAddress(transportLayer["srv_ip"].GetString())) {
                m_ip = transportLayer["srv_ip"].GetString();

                printf("Using local IP address: %s\n", m_ip.c_str());

                m_bindOnIp = true;
            }
            else {
                printf("transport_layer.srv_ip is not a valid IP address -> ignore\n");
                Logger::getLogger()->warn("transport_layer.srv_ip has invalid type -> not using TLS");
            }

        }
    }

    if (applicationLayer.HasMember("ca_asdu_size")) {
        if (applicationLayer["ca_asdu_size"].IsInt()) {
            int caSize = applicationLayer["ca_asdu_size"].GetInt();

            if (caSize > 0 && caSize < 3) {
                m_caSize = caSize;
            }
            else {
                printf("application_layer.ca_asdu_size has invalid value -> using default value (2)\n");
                Logger::getLogger()->warn("application_layer.ca_asdu_size has invalid value -> using default value (2");
            }
        }
        else {
            printf("application_layer.ca_asdu_size has invalid type -> using default value (2)\n");
            Logger::getLogger()->warn("application_layer.ca_asdu_size has invalid type -> using default value (2)");
        }
    }

    if (applicationLayer.HasMember("ioaddr_size")) {
        if (applicationLayer["ioaddr_size"].IsInt()) {
            int ioaSize = applicationLayer["ioaddr_size"].GetInt();

            if (ioaSize > 0 && ioaSize < 4) {
                m_ioaSize = ioaSize;
            }
            else {
                printf("application_layer.ioaddr_size has invalid value -> using default value (3)\n");
                Logger::getLogger()->warn("application_layer.ioaddr_size has invalid value -> using default value (3)");
            }
        }
        else {
            printf("application_layer.ioaddr_size has invalid type -> using default value (3)\n");
            Logger::getLogger()->warn("application_layer.ioaddr_size has invalid type -> using default value (3)");
        }
    }

    if (applicationLayer.HasMember("asdu_size")) {
        if (applicationLayer["asdu_size"].IsInt()) {
            int asduSize = applicationLayer["asdu_size"].GetInt();

            if (asduSize == 0 || (asduSize > 10 && asduSize < 254)) {
                m_asduSize = asduSize;
            }
            else {
                printf("application_layer.asdu_size has invalid value -> using default value (3)\n");
                Logger::getLogger()->warn("application_layer.asdu_size has invalid value -> using default value (3)");
            }
        }
        else {
            printf("application_layer.asdu_size has invalid type -> using default value (3)\n");
            Logger::getLogger()->warn("application_layer.asdu_size has invalid type -> using default value (3)");
        }
    }

    if (applicationLayer.HasMember("time_sync")) {
        if (applicationLayer["time_sync"].IsBool()) {
            m_timeSync = applicationLayer["time_sync"].GetBool();
        }
        else {
            printf("application_layer.time_sync has invalid type -> using default value (false)\n");
            Logger::getLogger()->warn("application_layer.time_sync has invalid type -> using default value (false)");
        }
    }

    if (applicationLayer.HasMember("filter_list")) {
        if (applicationLayer["filter_list"].IsArray()) {

            for (const Value& filter : applicationLayer["filter_list"].GetArray()) {
                if (filter.IsObject()) {
                    if (filter.HasMember("orig_addr")) {
                        if (filter["orig_addr"].IsInt()) {
                            int oaValue = filter["orig_addr"].GetInt();

                            if (oaValue >= 0 && oaValue < 256) {
                                m_allowedOriginators[oaValue] = oaValue;
                                m_filterOriginators = true;
                            }
                            else {
                                printf("application_layer.filter_list: invalid OA address value\n");
                                Logger::getLogger()->error("application_layer.filter_list: invalid OA address value");
                            }
                        }
                    }
                }
                else {
                    printf("application_layer.filter_list element not an object\n");
                    Logger::getLogger()->error("application_layer.filter_list element not an object");
                }
            }
                
        }
        else {
            printf("application_layer.filter_list is not an array\n");
            Logger::getLogger()->error("application_layer.filter_list is not an array");
        }
    }

    if (applicationLayer.HasMember("asdu_queue_size")) {
        if (applicationLayer["asdu_queue_size"].IsInt()) {
            int asduQueueSize = applicationLayer["asdu_queue_size"].GetInt();

            if (asduQueueSize > 0) {
                m_asduQueueSize = asduQueueSize;
            }
            else {
                printf("application_layer.asdu_queue_size has invalid value -> using default value (100)\n");
                Logger::getLogger()->warn("application_layer.asdu_queue_size has invalid value -> using default value (100)");
            }
        }
        else {
            printf("application_layer.asdu_queue_size has invalid type -> using default value (100)\n");
            Logger::getLogger()->warn("application_layer.asdu_queue_size has invalid type -> using default value (100)");
        }
    }

    if (applicationLayer.HasMember("accept_cmd_with_time")) {
        if (applicationLayer["accept_cmd_with_time"].IsInt()) {
            int acceptCmdWithTime = applicationLayer["accept_cmd_with_time"].GetInt();

            if (acceptCmdWithTime > -1 && acceptCmdWithTime < 3) {
                m_allowedCommands = acceptCmdWithTime;
            }
            else {
                printf("application_layer.accept_cmd_with_time has invalid value -> using default: only commands with timestamp allowed\n");
                Logger::getLogger()->warn("application_layer.accept_cmd_with_time has invalid value -> using default: only commands with timestamp allowed");
            }
        }
        else {
            printf("application_layer.accept_cmd_with_time has invalid type -> using default: only commands with timestamp allowed\n");
            Logger::getLogger()->warn("application_layer.accept_cmd_with_time has invalid type -> using default: only commands with timestamp allowed");
        }
    }
 
    m_protocolConfigComplete = true;
}

void
IEC104Config::importExchangeConfig(const string& exchangeConfig)
{
    m_exchangeConfigComplete = false;

    deleteExchangeDefinitions();

    m_exchangeDefinitions = new std::map<int, std::map<int, IEC104DataPoint*>>();

    Document document;

    if (document.Parse(const_cast<char*>(exchangeConfig.c_str())).HasParseError()) {
        Logger::getLogger()->fatal("Parsing error in data exchange configuration");

        return;
    }

    if (!document.IsObject())
        return;

    if (!document.HasMember(JSON_EXCHANGED_DATA) || !document[JSON_EXCHANGED_DATA].IsObject()) {
        return;
    }

    const Value& exchangeData = document[JSON_EXCHANGED_DATA];

    if (!exchangeData.HasMember(JSON_DATAPOINTS) || !exchangeData[JSON_DATAPOINTS].IsArray()) {
        return;
    }

    const Value& datapoints = exchangeData[JSON_DATAPOINTS];

    for (const Value& datapoint : datapoints.GetArray()) {

        if (!datapoint.IsObject()) return;

        if (!datapoint.HasMember(JSON_LABEL) || !datapoint[JSON_LABEL].IsString()) return;

        string label = datapoint[JSON_LABEL].GetString();

        if (!datapoint.HasMember(JSON_PROTOCOLS) || !datapoint[JSON_PROTOCOLS].IsArray()) return;

        for (const Value& protocol : datapoint[JSON_PROTOCOLS].GetArray()) {
            
            if (!protocol.HasMember(JSON_PROT_NAME) || !protocol[JSON_PROT_NAME].IsString()) return;
            
            string protocolName = protocol[JSON_PROT_NAME].GetString();

            if (protocolName == PROTOCOL_IEC104) {

                if (!protocol.HasMember(JSON_PROT_ADDR) || !protocol[JSON_PROT_ADDR].IsString()) return;
                if (!protocol.HasMember(JSON_PROT_TYPEID) || !protocol[JSON_PROT_TYPEID].IsString()) return;

                string address = protocol[JSON_PROT_ADDR].GetString();
                string typeIdStr = protocol[JSON_PROT_TYPEID].GetString();

                printf("  address: %s type: %s\n", address.c_str(), typeIdStr.c_str());

                size_t sepPos = address.find("-");

                if (sepPos != std::string::npos) {
                    std::string caStr = address.substr(0, sepPos);
                    std::string ioaStr = address.substr(sepPos + 1);

                    int ca = std::stoi(caStr);
                    int ioa = std::stoi(ioaStr);

                    printf("    CA: %i IOA: %i\n", ca, ioa);

                    int typeId = IEC104DataPoint::getTypeIdFromString(typeIdStr);

                    int dataType = IEC104DataPoint::typeIdToDataType(typeId);

                    bool isCommand = IEC104DataPoint::isSupportedCommandType(typeId);
                    bool isMonitoring = IEC104DataPoint::isSupportedMonitoringType(typeId);

                    if (isCommand || isMonitoring) {
                        IEC104DataPoint* newDp = new IEC104DataPoint(label, ca, ioa, dataType, isCommand);
               
                        (*m_exchangeDefinitions)[ca][ioa] = newDp;
                    }
                    else {
                        printf("Skip datapoint %i:%i\n", ca, ioa);
                    }
                }
            }
        }
    }

    m_exchangeConfigComplete = true;
}

int IEC104Config::TcpPort()
{
    if (m_tcpPort == -1) {
        //TODO check for TLS
        return 2404;
    }
    else {
        return m_tcpPort;
    }
}

bool IEC104Config::IsOriginatorAllowed(int oa)
{
    if (m_filterOriginators) {
        if (m_allowedOriginators.count(oa) > 0)
            return true;
        else {
            printf("OA %i not allowed!\n", oa);
            return false;
        }
    }
    else {
        return true;
    }
}

bool IEC104Config::AllowCmdWithTime()
{
    if (m_allowedCommands == 1 || m_allowedCommands == 2) {
        return true;
    }
    else {
        return false;
    }
}

bool IEC104Config::AllowCmdWithoutTime()
{
    if (m_allowedCommands == 0 || m_allowedCommands == 2) {
        return true;
    }
    else {
        return false;
    }
}