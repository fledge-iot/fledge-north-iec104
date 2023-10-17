#include <sstream>
#include <algorithm>

#include <arpa/inet.h>
#include <iec104_datapoint.hpp>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

#include "iec104_config.hpp"
#include "iec104_utility.hpp"

using namespace rapidjson;

#define JSON_EXCHANGED_DATA "exchanged_data"
#define JSON_DATAPOINTS "datapoints"
#define JSON_PROTOCOLS "protocols"
#define JSON_LABEL "label"

#define PROTOCOL_IEC104 "iec104"
#define JSON_PROT_NAME "name"
#define JSON_PROT_ADDR "address"
#define JSON_PROT_TYPEID "typeid"
#define JSON_PROT_GI_GROUPS "gi_groups"

IEC104Config::IEC104Config()
{
    m_exchangeConfigComplete = false;
    m_protocolConfigComplete = false;
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

IEC104Config::SouthPluginMonitor::SouthPluginMonitor(std::string& assetName)
{
    m_assetName = assetName;
}

IEC104Config::~IEC104Config()
{
    deleteExchangeDefinitions();

    for (auto southPluginMonitor : m_monitoredSouthPlugins) {
        delete southPluginMonitor;
    }
}

bool
IEC104Config::isValidIPAddress(const std::string& addrStr)
{
    // see https://stackoverflow.com/questions/318236/how-do-you-validate-that-a-string-is-a-valid-ipv4-address-in-c
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, addrStr.c_str(), &(sa.sin_addr));

    return (result == 1);
}

void
IEC104Config::importProtocolConfig(const std::string& protocolConfig)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Config::importProtocolConfig -";
    m_protocolConfigComplete = false;

    Document document;

    if (document.Parse(const_cast<char*>(protocolConfig.c_str())).HasParseError()) {
        Iec104Utility::log_fatal("%s Parsing error in protocol_stack json, offset %u: %s", beforeLog.c_str(),
                                    static_cast<unsigned>(document.GetErrorOffset()), GetParseError_En(document.GetParseError()));
        return;
    }

    if (!document.IsObject()) {
        Iec104Utility::log_fatal("%s Root is not an object", beforeLog.c_str());
        return;
    }

    if (!document.HasMember("protocol_stack") || !document["protocol_stack"].IsObject()) {
        Iec104Utility::log_fatal("%s protocol_stack does not exist or is not an object", beforeLog.c_str());
        return;
    }

    const Value& protocolStack = document["protocol_stack"];

    if (!protocolStack.HasMember("transport_layer") || !protocolStack["transport_layer"].IsObject()) {
        Iec104Utility::log_fatal("%s transport_layer does not exist or is not an object", beforeLog.c_str());
        return;
    }

    if (!protocolStack.HasMember("application_layer") || !protocolStack["application_layer"].IsObject()) {
        Iec104Utility::log_fatal("%s application_layer does not exist or is not an object", beforeLog.c_str());
        return;
    }

    const Value& transportLayer = protocolStack["transport_layer"];
    const Value& applicationLayer = protocolStack["application_layer"];

    if (protocolStack.HasMember("south_monitoring")) {
        const Value& southMonitoring = protocolStack["south_monitoring"];

        if (southMonitoring.IsArray()) {
            for (const Value& southMonInst : southMonitoring.GetArray()) {;

                if (southMonInst.HasMember("asset")) {
                    if (southMonInst["asset"].IsString()) {
                        std::string assetName = southMonInst["asset"].GetString();

                        SouthPluginMonitor* monitor = new SouthPluginMonitor(assetName);

                        m_monitoredSouthPlugins.push_back(monitor);
                    }
                    else {
                        Iec104Utility::log_error("%s south_monitoring \"asset\" element is not a string", beforeLog.c_str());
                    }
                }
                else {
                    Iec104Utility::log_error("%s south_monitoring is missing \"asset\" element", beforeLog.c_str());
                }
            }
        }
    }

    if (transportLayer.HasMember("redundancy_groups")) {

        if (transportLayer["redundancy_groups"].IsArray()) {

            const Value& redundancyGroups = transportLayer["redundancy_groups"];

            for (const Value& redGroup : redundancyGroups.GetArray()) {
                
                if (!redGroup.IsObject()) {
                    Iec104Utility::log_error("%s redundancy_groups element is not an object -> ignore", beforeLog.c_str());
                    continue;
                }
                
                char* redGroupName = nullptr;

                if (redGroup.HasMember("rg_name")) {
                    if (redGroup["rg_name"].IsString()) {
                        std::string rgName = redGroup["rg_name"].GetString();

                        redGroupName = strdup(rgName.c_str());
                    }
                }
                if (redGroupName == nullptr) {
                    Iec104Utility::log_error("%s rg_name does not exist or is not a string -> ignore", beforeLog.c_str());
                    continue;
                }

                CS104_RedundancyGroup redundancyGroup = CS104_RedundancyGroup_create(redGroupName);
                
                Iec104Utility::log_debug("%s Adding red group with name: %s", beforeLog.c_str(), redGroupName);

                free(redGroupName);

                if (redGroup.HasMember("connections") && redGroup["connections"].IsArray()) {
                    for (const Value& con : redGroup["connections"].GetArray()) {
                        if(!con.IsObject()) {
                            Iec104Utility::log_error("%s  connections element is not an object -> ignore", beforeLog.c_str());
                            continue;
                        }
                        if (con.HasMember("clt_ip") && con["clt_ip"].IsString()) {
                            std::string cltIp = con["clt_ip"].GetString();

                            if (isValidIPAddress(cltIp)) {
                                CS104_RedundancyGroup_addAllowedClient(redundancyGroup, cltIp.c_str());
                                Iec104Utility::log_debug("%s  add to group: %s", beforeLog.c_str(), cltIp.c_str());
                            }
                            else {
                                Iec104Utility::log_error("%s  %s is not a valid IP address -> ignore", beforeLog.c_str(),
                                                        cltIp.c_str());
                            }
                        }
                        else {
                            Iec104Utility::log_error("%s  clt_ip does not exist or is not a string -> ignore",
                                                    beforeLog.c_str());
                            continue;
                        }
                    }
                }
                else {
                    Iec104Utility::log_debug("%s  connections does not exist or is not an array -> adding fallback group",
                                            beforeLog.c_str());
                }

                m_configuredRedundancyGroups.push_back(redundancyGroup);
            }
        }
        else {
            Iec104Utility::log_fatal("%s redundancy_groups is not an array -> ignore redundancy groups", beforeLog.c_str());
        }
    }

    if (transportLayer.HasMember("mode")) {
        if (transportLayer["mode"].IsString()) {
            std::string modeValue = transportLayer["mode"].GetString();

            if (modeValue == "accept_always") {
                m_mode = IEC104Config::Mode::CONNECT_ALWAYS;
            }
            else if (modeValue == "accept_if_south_connx_started") {
                m_mode = IEC104Config::Mode::CONNECT_IF_SOUTH_CONNX_STARTED;
            }
            else {
                Iec104Utility::log_warn("%s transport_layer.mode has unknown value '%s' -> using mode: connect always",
                                        beforeLog.c_str(), modeValue.c_str());
            }
        }
        else {
            Iec104Utility::log_warn("%s transport_layer.mode is not a string -> using mode: connect always", beforeLog.c_str());
        }
    } 

    if (transportLayer.HasMember("port")) {
        if (transportLayer["port"].IsInt()) {
            int tcpPort = transportLayer["port"].GetInt();

            if (tcpPort > 0 && tcpPort < 65536) {
                m_tcpPort = tcpPort;
            }
            else {
                Iec104Utility::log_warn("%s transport_layer.port value out of range [1..65535]: %d -> using default port (%d)",
                                        beforeLog.c_str(), tcpPort, m_defaultTcpPort);
            }
        }
        else {
            Iec104Utility::log_warn("%s transport_layer.port in not an integer -> using default port (%d)", beforeLog.c_str(),
                                    m_defaultTcpPort);
        }
    }

    if (transportLayer.HasMember("k_value")) {
        if (transportLayer["k_value"].IsInt()) {
            int kValue = transportLayer["k_value"].GetInt();

            if (kValue > 0 && kValue < 32768) {
                m_k = kValue;
            }
            else {
                Iec104Utility::log_warn("%s transport_layer.k_value value out of range [1..32767]: %d -> using default value (%d)",
                                        beforeLog.c_str(), kValue, m_k);
            }
        }
        else {
            Iec104Utility::log_warn("%s transport_layer.k_value is not an integer -> using default value (%d)", beforeLog.c_str(), m_k);
        }
    }

    if (transportLayer.HasMember("w_value")) {
        if (transportLayer["w_value"].IsInt()) {
            int wValue = transportLayer["w_value"].GetInt();

            if (wValue > 0 && wValue < 32768) {
                m_w = wValue;
            }
            else {
                Iec104Utility::log_warn("%s transport_layer.w_value value out of range [1..32767]: %d -> using default value (%d)",
                                        beforeLog.c_str(), wValue, m_w);
            }
        }
        else {
            Iec104Utility::log_warn("%s transport_layer.w_value is not an integer -> using default value (%d)", beforeLog.c_str(), m_w);
        }
    }

    if (transportLayer.HasMember("t0_timeout")) {
        if (transportLayer["t0_timeout"].IsInt()) {
            int t0Timeout = transportLayer["t0_timeout"].GetInt();

            if (t0Timeout > 0 && t0Timeout < 256) {
                m_t0 = t0Timeout;
            }
            else {
                Iec104Utility::log_warn("%s transport_layer.t0_timeout value out of range [1..255]: %d -> using default value (%d)",
                                        beforeLog.c_str(), t0Timeout, m_t0);
            }
        }
        else {
            Iec104Utility::log_warn("%s transport_layer.t0_timeout is not an integer -> using default value (%d)",
                                    beforeLog.c_str(), m_t0);
        }
    }

    if (transportLayer.HasMember("t1_timeout")) {
        if (transportLayer["t1_timeout"].IsInt()) {
            int t1Timeout = transportLayer["t1_timeout"].GetInt();

            if (t1Timeout > 0 && t1Timeout < 256) {
                m_t1 = t1Timeout;
            }
            else {
                Iec104Utility::log_warn("%s transport_layer.t1_timeout value out of range [1..255]: %d -> using default value (%d)",
                                        beforeLog.c_str(), t1Timeout, m_t1);
            }
        }
        else {
            Iec104Utility::log_warn("%s transport_layer.t1_timeout is not an integer -> using default value (%d)",
                                    beforeLog.c_str(), m_t1);
        }
    }

    if (transportLayer.HasMember("t2_timeout")) {
        if (transportLayer["t2_timeout"].IsInt()) {
            int t2Timeout = transportLayer["t2_timeout"].GetInt();

            if (t2Timeout > 0 && t2Timeout < 256) {
                m_t2 = t2Timeout;
            }
            else {
                Iec104Utility::log_warn("%s transport_layer.t2_timeout value out of range [1..255]: %d -> using default value (%d)",
                                        beforeLog.c_str(), t2Timeout, m_t2);
            }
        }
        else {
            Iec104Utility::log_warn("%s transport_layer.t2_timeout is not an integer -> using default value (%d)",
                                    beforeLog.c_str(), m_t2);
        }
    }

    if (transportLayer.HasMember("t3_timeout")) {
        if (transportLayer["t3_timeout"].IsInt()) {
            int t3Timeout = transportLayer["t3_timeout"].GetInt();

            if (t3Timeout > -1) {
                m_t3 = t3Timeout;
            }
            else {
                Iec104Utility::log_warn("%s transport_layer.t3_timeout value out of range [0..+Inf]: %d -> using default value (%d)",
                                        beforeLog.c_str(), t3Timeout, m_t3);
            }
        }
        else {
            Iec104Utility::log_warn("%s transport_layer.t3_timeout is not an integer -> using default value (%d)",
                                    beforeLog.c_str(), m_t3);
        }
    }

    if (transportLayer.HasMember("tls")) {
        if (transportLayer["tls"].IsBool()) {
            m_useTls = transportLayer["tls"].GetBool();
        }
        else {
            Iec104Utility::log_warn("%s transport_layer.tls is not a bool -> not using TLS", beforeLog.c_str());
        }
    }

    if (transportLayer.HasMember("srv_ip")) {
        if (transportLayer["srv_ip"].IsString()) {
            if (isValidIPAddress(transportLayer["srv_ip"].GetString())) {
                m_ip = transportLayer["srv_ip"].GetString();
                Iec104Utility::log_info("%s Using local IP address: %s", beforeLog.c_str(), m_ip.c_str());
                m_bindOnIp = true;
            }
            else {
                Iec104Utility::log_warn("%s transport_layer.srv_ip is not a string -> not using TLS", beforeLog.c_str());
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
                Iec104Utility::log_warn("%s application_layer.ca_asdu_size value out of range [1..2]: %d -> using default value (%d)",
                                        beforeLog.c_str(), caSize, m_caSize);
            }
        }
        else {
            Iec104Utility::log_warn("%s application_layer.ca_asdu_size is not an integer -> using default value (%d)",
                                    beforeLog.c_str(), m_caSize);
        }
    }

    if (applicationLayer.HasMember("ioaddr_size")) {
        if (applicationLayer["ioaddr_size"].IsInt()) {
            int ioaSize = applicationLayer["ioaddr_size"].GetInt();

            if (ioaSize > 0 && ioaSize < 4) {
                m_ioaSize = ioaSize;
            }
            else {
                Iec104Utility::log_warn("%s application_layer.ioaddr_size value out of range [1..3]: %d -> using default value (%d)",
                                        beforeLog.c_str(), ioaSize, m_ioaSize);
            }
        }
        else {
            Iec104Utility::log_warn("%s application_layer.ioaddr_size is not an integer -> using default value (%d)",
                                    beforeLog.c_str(), m_ioaSize);
        }
    }

    if (applicationLayer.HasMember("asdu_size")) {
        if (applicationLayer["asdu_size"].IsInt()) {
            int asduSize = applicationLayer["asdu_size"].GetInt();

            if (asduSize == 0 || (asduSize > 10 && asduSize < 254)) {
                m_asduSize = asduSize;
            }
            else {
                Iec104Utility::log_warn("%s application_layer.asdu_size value out of range [0,11..253]: %d -> using default value (%d)",
                                        beforeLog.c_str(), asduSize, m_asduSize);
            }
        }
        else {
            Iec104Utility::log_warn("%s application_layer.asdu_size is not an integer -> using default value (%d)",
                                    beforeLog.c_str(), m_asduSize);
        }
    }

    if (applicationLayer.HasMember("time_sync")) {
        if (applicationLayer["time_sync"].IsBool()) {
            m_timeSync = applicationLayer["time_sync"].GetBool();
        }
        else {
            Iec104Utility::log_warn("%s application_layer.time_sync is not a bool -> using default value (%s)", beforeLog.c_str(),
                                    (m_timeSync?"true":"false"));
        }
    }

    if (applicationLayer.HasMember("filter_list")) {
        if (applicationLayer["filter_list"].IsArray()) {
            for (const Value& filter : applicationLayer["filter_list"].GetArray()) {
                if (filter.IsObject()) {
                    if (filter.HasMember("orig_addr") && filter["orig_addr"].IsInt()) {
                        int oaValue = filter["orig_addr"].GetInt();

                        if (oaValue >= 0 && oaValue < 256) {
                            m_allowedOriginators[oaValue] = oaValue;
                            m_filterOriginators = true;
                        }
                        else {
                            Iec104Utility::log_error("%s application_layer.filter_list: OA address value out of ragne [1..255]: %d",
                                                    beforeLog.c_str(), oaValue);
                        }
                    }
                    else {
                        Iec104Utility::log_error("%s application_layer.filter_list: orig_addr does not exist or is not an integer",
                                                    beforeLog.c_str());
                    }
                }
                else {
                    Iec104Utility::log_error("%s application_layer.filter_list element is not an object", beforeLog.c_str());
                }
            }
        }
        else {
            Iec104Utility::log_error("%s application_layer.filter_list is not an array", beforeLog.c_str());
        }
    }

    if (applicationLayer.HasMember("asdu_queue_size")) {
        if (applicationLayer["asdu_queue_size"].IsInt()) {
            int asduQueueSize = applicationLayer["asdu_queue_size"].GetInt();
            if (asduQueueSize > 0) {
                m_asduQueueSize = asduQueueSize;
            }
            else {
                Iec104Utility::log_warn(
                    "%s application_layer.asdu_queue_size value out of range [1..+Inf]: %d -> using default value (%d)",             
                    beforeLog.c_str(), asduQueueSize, m_asduQueueSize);
            }
        }
        else {
            Iec104Utility::log_warn("%s application_layer.asdu_queue_size is not an integer -> using default value (%d)",
                                    beforeLog.c_str(), m_asduQueueSize);
        }
    }

    if (applicationLayer.HasMember("accept_cmd_with_time")) {
        if (applicationLayer["accept_cmd_with_time"].IsInt()) {
            int acceptCmdWithTime = applicationLayer["accept_cmd_with_time"].GetInt();
            if (acceptCmdWithTime > -1 && acceptCmdWithTime < 3) {
                m_allowedCommands = acceptCmdWithTime;
            }
            else {
                Iec104Utility::log_warn(
                    "%s application_layer.accept_cmd_with_time value out of range [0..2]: %d -> using default: only commands with timestamp allowed (%d)",
                    beforeLog.c_str(), acceptCmdWithTime, m_allowedCommands);
            }
        }
        else {
            Iec104Utility::log_warn(
                "%s application_layer.accept_cmd_with_time is not an integer -> using default: only commands with timestamp allowed (%d)",
                beforeLog.c_str(), m_allowedCommands);
        }
    }

    if (applicationLayer.HasMember("cmd_recv_timeout")) {
        if (applicationLayer["cmd_recv_timeout"].IsInt()) {
            int cmdRecvTimeout = applicationLayer["cmd_recv_timeout"].GetInt();
            if (cmdRecvTimeout >= 0) {
                m_cmdRecvTimeout = cmdRecvTimeout;
            }
            else {
                Iec104Utility::log_warn("%s application_layer.cmd_recv_timeout value out of range [0..+Inf]: %d -> using default: disabled (%d)",
                                        beforeLog.c_str(), cmdRecvTimeout, m_cmdRecvTimeout);
            }
        }
        else {
             Iec104Utility::log_warn("%s application_layer.cmd_recv_timeout is not an integer -> using default: disabled (%d)",
                                    beforeLog.c_str(), m_cmdRecvTimeout);
        }
    }

    if (applicationLayer.HasMember("cmd_exec_timeout")) {
        if (applicationLayer["cmd_exec_timeout"].IsInt()) {
            int cmdExecTimeout = applicationLayer["cmd_exec_timeout"].GetInt();
            if (cmdExecTimeout >= 0) {
                m_cmdExecTimeout = cmdExecTimeout;
            }
            else {
                Iec104Utility::log_warn("%s application_layer.cmd_exec_timeout value out of range [0..+Inf]: %d -> using default: %d seconds",
                                        beforeLog.c_str(), cmdExecTimeout, m_cmdExecTimeout);
            }
        }
        else {
             Iec104Utility::log_warn("%s application_layer.cmd_exec_timeout is not an integer -> using default: %d seconds",
                                    beforeLog.c_str(), m_cmdExecTimeout);
        }
    }

    if (applicationLayer.HasMember("cmd_dest")) {
        if (applicationLayer["cmd_dest"].IsString()) {
            m_cmdDest = applicationLayer["cmd_dest"].GetString();
        }
        else {
            Iec104Utility::log_warn("%s application_layer.cmd_dest is not a string -> broadcast commands", beforeLog.c_str());
        }   
    }

    m_protocolConfigComplete = true;
}

void
IEC104Config::importExchangeConfig(const std::string& exchangeConfig)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Config::importExchangeConfig -";
    m_exchangeConfigComplete = false;

    deleteExchangeDefinitions();

    m_exchangeDefinitions = new std::map<int, std::map<int, IEC104DataPoint*>>();

    Document document;

    if (document.Parse(const_cast<char*>(exchangeConfig.c_str())).HasParseError()) {
        Iec104Utility::log_fatal("%s Parsing error in exchanged_data json, offset %u: %s", beforeLog.c_str(),
                                    static_cast<unsigned>(document.GetErrorOffset()), GetParseError_En(document.GetParseError()));
        return;
    }

    if (!document.IsObject()) {
        Iec104Utility::log_fatal("%s Root is not an object", beforeLog.c_str());
        return;
    }
        

    if (!document.HasMember(JSON_EXCHANGED_DATA) || !document[JSON_EXCHANGED_DATA].IsObject()) {
        Iec104Utility::log_fatal("%s %s does not exist or is not an object", beforeLog.c_str(), JSON_EXCHANGED_DATA);
        return;
    }

    const Value& exchangeData = document[JSON_EXCHANGED_DATA];

    if (!exchangeData.HasMember(JSON_DATAPOINTS) || !exchangeData[JSON_DATAPOINTS].IsArray()) {
        Iec104Utility::log_fatal("%s %s does not exist or is not an array", beforeLog.c_str(), JSON_DATAPOINTS);
        return;
    }

    const Value& datapoints = exchangeData[JSON_DATAPOINTS];

    for (const Value& datapoint : datapoints.GetArray()) {

        if (!datapoint.IsObject()) {
            Iec104Utility::log_error("%s %s element is not an object", beforeLog.c_str(), JSON_DATAPOINTS);
            return;
        } 

        if (!datapoint.HasMember(JSON_LABEL) || !datapoint[JSON_LABEL].IsString()) {
            Iec104Utility::log_error("%s %s does not exist or is not a string", beforeLog.c_str(), JSON_LABEL);
            return;
        }

        std::string label = datapoint[JSON_LABEL].GetString();

        if (!datapoint.HasMember(JSON_PROTOCOLS) || !datapoint[JSON_PROTOCOLS].IsArray()) {
            Iec104Utility::log_error("%s %s does not exist or is not an array", beforeLog.c_str(), JSON_PROTOCOLS);
            return;
        }

        for (const Value& protocol : datapoint[JSON_PROTOCOLS].GetArray()) {
            
            if (!datapoint.IsObject()) {
                Iec104Utility::log_error("%s %s element is not an object", beforeLog.c_str(), JSON_PROTOCOLS);
                return;
            } 
            
            if (!protocol.HasMember(JSON_PROT_NAME) || !protocol[JSON_PROT_NAME].IsString()) {
                Iec104Utility::log_error("%s %s does not exist or is not a string", beforeLog.c_str(), JSON_PROT_NAME);
                return;
            }
            
            std::string protocolName = protocol[JSON_PROT_NAME].GetString();

            if (protocolName == PROTOCOL_IEC104) {

                if (!protocol.HasMember(JSON_PROT_ADDR) || !protocol[JSON_PROT_ADDR].IsString()) {
                    Iec104Utility::log_error("%s %s does not exist or is not a string", beforeLog.c_str(), JSON_PROT_ADDR);
                    return;
                }
                if (!protocol.HasMember(JSON_PROT_TYPEID) || !protocol[JSON_PROT_TYPEID].IsString()) {
                    Iec104Utility::log_error("%s %s does not exist or is not a string", beforeLog.c_str(), JSON_PROT_TYPEID);
                    return;
                }

                int32_t gi_groups = 0;

                if (protocol.HasMember(JSON_PROT_GI_GROUPS)) {

                    if(protocol[JSON_PROT_GI_GROUPS].IsString()) {

                        std::string gi_groups_member = protocol[JSON_PROT_GI_GROUPS].GetString();

                        if(gi_groups_member == "") {
                          gi_groups = 0; 
                        }
                        else {
                            std::stringstream ss(gi_groups_member);
                            while (ss.good()){

                                std::string substr;
                                getline( ss, substr, ',' );

                                int group = 0;

                                if (substr == "station") {
                                    group = 0;
                                }   
                                else if (all_of(substr.begin(), substr.end(), ::isdigit)) {
                                    group = stoi(substr);

                                    if(group <= 0 || group >= 17){
                                        Iec104Utility::log_warn("%s %s value out of range [1..16]: %d, defaulting to station.",
                                                                beforeLog.c_str(), JSON_PROT_GI_GROUPS, group, gi_groups);
                                        gi_groups = 1;   
                                        break;
                                    }
                                }
                                else {
                                    Iec104Utility::log_warn("%s %s value invalid, defaulting to station.", beforeLog.c_str(),
                                                            JSON_PROT_GI_GROUPS);
                                    gi_groups = 1;   
                                    break;
                                }

                                gi_groups |= (1 << group); 
                            }  
                        }
                    }
                    else {
                        Iec104Utility::log_warn("%s %s value is not a string, defaulting to station.", beforeLog.c_str(),
                                                JSON_PROT_GI_GROUPS);
                        gi_groups = 1;   
                        break;
                    } 
                }
                else {
                    gi_groups = 1;
                }

                Iec104Utility::log_debug("%s GI GROUPS = %i", beforeLog.c_str(), gi_groups);    

                std::string address = protocol[JSON_PROT_ADDR].GetString();
                std::string typeIdStr = protocol[JSON_PROT_TYPEID].GetString();

                Iec104Utility::log_debug("%s  address: %s type: %s", beforeLog.c_str(), address.c_str(), typeIdStr.c_str());

                size_t sepPos = address.find("-");

                if (sepPos != std::string::npos) {
                    std::string caStr = address.substr(0, sepPos);
                    std::string ioaStr = address.substr(sepPos + 1);

                    int ca = 0;
                    int ioa = 0;
                    try {
                        ca = std::stoi(caStr);
                        ioa = std::stoi(ioaStr);
                    } catch (const std::invalid_argument &e) {
                        Iec104Utility::log_error("%s Cannot convert ca '%s' or ioa '%s' to integer: %s",
                                                beforeLog.c_str(), caStr.c_str(), ioaStr.c_str(), e.what());
                        return;
                    } catch (const std::out_of_range &e) {
                        Iec104Utility::log_error("%s Cannot convert ca '%s' or ioa '%s' to integer: %s",
                                                beforeLog.c_str(), caStr.c_str(), ioaStr.c_str(), e.what());
                        return;
                    }

                    Iec104Utility::log_debug("%s    CA: %i IOA: %i", beforeLog.c_str(), ca, ioa);

                    int typeId = IEC104DataPoint::getTypeIdFromString(typeIdStr);
                    int dataType = IEC104DataPoint::typeIdToDataType(typeId);

                    bool isCommand = IEC104DataPoint::isSupportedCommandType(typeId);
                    bool isMonitoring = IEC104DataPoint::isSupportedMonitoringType(typeId);

                    if (isCommand || isMonitoring) {
                        IEC104DataPoint* newDp = new IEC104DataPoint(label, ca, ioa, dataType, isCommand, gi_groups);
               
                        (*m_exchangeDefinitions)[ca][ioa] = newDp;
                    }
                    else {
                        Iec104Utility::log_debug("%s Skip datapoint %i:%i as it is not a supported type: %s",
                                                beforeLog.c_str(), ca, ioa, typeIdStr.c_str());
                    }
                }
                else {
                    Iec104Utility::log_error("%s %s value does not follow format 'XXX-YYY'", beforeLog.c_str(), JSON_PROT_ADDR);
                    return;
                }
            }
        }
    }

    m_exchangeConfigComplete = true;
}

void
IEC104Config::importTlsConfig(const std::string& tlsConfig)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Config::importTlsConfig -";
    Document document;

    if (document.Parse(const_cast<char*>(tlsConfig.c_str())).HasParseError()) {
        Iec104Utility::log_fatal("%s Parsing error in tls_conf json, offset %u: %s", beforeLog.c_str(),
                                static_cast<unsigned>(document.GetErrorOffset()), GetParseError_En(document.GetParseError()));
        return;
    }
       
    if (!document.IsObject()) {
        Iec104Utility::log_fatal("%s Root is not an object", beforeLog.c_str());
        return;
    }
        

    if (!document.HasMember("tls_conf") || !document["tls_conf"].IsObject()) {
        Iec104Utility::log_debug("%s tls_conf does not exist or is not an object", beforeLog.c_str());
        return;
    }

    const Value& tlsConf = document["tls_conf"];

    if (tlsConf.HasMember("private_key") && tlsConf["private_key"].IsString()) {
        m_privateKey = tlsConf["private_key"].GetString();
    }
    else {
        Iec104Utility::log_warn("%s private_key does not exist or is not a string", beforeLog.c_str());
    }

    if (tlsConf.HasMember("own_cert") && tlsConf["own_cert"].IsString()) {
        m_ownCertificate = tlsConf["own_cert"].GetString();
    }
    else {
        Iec104Utility::log_warn("%s own_cert does not exist or is not a string", beforeLog.c_str());
    }

    if (tlsConf.HasMember("ca_certs") && tlsConf["ca_certs"].IsArray()) {

        const Value& caCerts = tlsConf["ca_certs"];

        for (const Value& caCert : caCerts.GetArray()) {
            if (!caCert.IsObject()) {
                Iec104Utility::log_warn("%s ca_certs element is not an object", beforeLog.c_str());
                continue;
            }
            
            if (caCert.HasMember("cert_file") && caCert["cert_file"].IsString()) {
                    std::string certFileName = caCert["cert_file"].GetString();
                    m_caCertificates.push_back(certFileName);
            }
            else {
                Iec104Utility::log_warn("%s ca_certs.cert_file does not exist or is not a string", beforeLog.c_str());
            }
        }
    }
    else {
        Iec104Utility::log_warn("%s ca_certs does not exist or is not an array", beforeLog.c_str());
    }

    if (tlsConf.HasMember("remote_certs") && tlsConf["remote_certs"].IsArray()) {

        const Value& remoteCerts = tlsConf["remote_certs"];

        for (const Value& remoteCert : remoteCerts.GetArray()) {
            if (!remoteCert.IsObject()) {
                Iec104Utility::log_warn("%s remote_certs element is not an object", beforeLog.c_str());
                continue;
            }

            if (remoteCert.HasMember("cert_file") && remoteCert["cert_file"].IsString()) {
                    std::string certFileName = remoteCert["cert_file"].GetString();

                    m_remoteCertificates.push_back(certFileName);
            }
            else {
                Iec104Utility::log_warn("%s remote_certs.cert_file does not exist or is not a string", beforeLog.c_str());
            }
        }
    }
    else {
        Iec104Utility::log_warn("%s remote_certs does not exist or is not an array", beforeLog.c_str());
    }
}

int IEC104Config::TcpPort()
{
    if (m_tcpPort == -1) {
        //TODO check for TLS
        return m_defaultTcpPort;
    }
    else {
        return m_tcpPort;
    }
}

bool IEC104Config::IsOriginatorAllowed(int oa)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Config::IsOriginatorAllowed -";
    if (m_filterOriginators) {
        if (m_allowedOriginators.count(oa) > 0)
            return true;
        else {
            Iec104Utility::log_warn("%s OA %i not allowed!", beforeLog.c_str(), oa);
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