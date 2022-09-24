#ifndef _IEC104SERVER_H
#define _IEC104SERVER_H

/*
 * Fledge IEC 104 north plugin.
 *
 * Copyright (c) 2020, RTE (https://www.rte-france.com)
 *
 * Released under the Apache 2.0 Licence
 *
 * Authors: Akli Rahmoun <akli.rahmoun at rte-france.com>, Michael Zillgith <michael.zillgith@mz-automation.de>
 */

// clang-format off
#include <reading.h>
#include <config_category.h>
#include <logger.h>
#include <plugin_api.h>
#include <string>
#include <vector>
#include <map>
#include "iec104_datapoint.hpp"
#include "lib60870/cs104_slave.h"
#include "lib60870/cs101_information_objects.h"
#include "lib60870/hal_thread.h"
#include "lib60870/hal_time.h"

#include "iec104_config.hpp"
// clang-format on

class IEC104Server
{
public:
    IEC104Server();
    ~IEC104Server();
    
    void setJsonConfig(const std::string& stackConfig,
                                 const std::string& dataExchangeConfig,
                                const std::string& tlsConfig);

    void configure(const ConfigCategory* conf);
    uint32_t send(const std::vector<Reading*>& readings);
    void stop();

    void registerControl(int (* operation)(char *operation, int paramCount, char *parameters[], ControlDestination destination, ...));

private:

    std::map<int, std::map<int, IEC104DataPoint*>> m_exchangeDefinitions;
    
    IEC104DataPoint* m_getDataPoint(int ca, int ioa, int typeId);
    void m_enqueueSpontDatapoint(IEC104DataPoint* dp, CS101_CauseOfTransmission cot, IEC60870_5_TypeID typeId);
    void m_updateDataPoint(IEC104DataPoint* dp, IEC60870_5_TypeID typeId, DatapointValue* value, CP56Time2a ts, uint8_t quality);

    bool checkTimestamp(CP56Time2a timestamp);
    bool forwardCommand(CS101_ASDU asdu, InformationObject command);

    static void printCP56Time2a(CP56Time2a time);
    static void rawMessageHandler(void* parameter, IMasterConnection connection,
                                  uint8_t* msg, int msgSize, bool sent);
    static bool clockSyncHandler(void* parameter, IMasterConnection connection,
                                 CS101_ASDU asdu, CP56Time2a newTime);

    void sendInterrogationResponse(IMasterConnection connection, CS101_ASDU asdu, int ca);

    static bool interrogationHandler(void* parameter,
                                     IMasterConnection connection,
                                     CS101_ASDU asdu, uint8_t qoi);
    static bool asduHandler(void* parameter, IMasterConnection connection,
                            CS101_ASDU asdu);
    static bool connectionRequestHandler(void* parameter,
                                         const char* ipAddress);
    static void connectionEventHandler(void* parameter, IMasterConnection con,
                                       CS104_PeerConnectionEvent event);
    CS104_Slave m_slave{};
    CS101_AppLayerParameters alParams;
    std::string m_name;
    Logger* m_log;
    IEC104Config* m_config;

    int (*m_oper)(char *operation, int paramCount, char *parameters[], ControlDestination destination, ...);
};

#endif