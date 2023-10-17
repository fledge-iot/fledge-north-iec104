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

#include <plugin_api.h>
#include <vector>
#include <map>
#include <mutex>
#include <thread>

#include "lib60870/cs104_slave.h"
#include "lib60870/cs101_information_objects.h"

#include "iec104_config.hpp"

// clang-format on

class Reading;
class ConfigCategory;
class IEC104DataPoint;
class Datapoint;
class DatapointValue;

class IEC104OutstandingCommand
{
public:

    IEC104OutstandingCommand(CS101_ASDU asdu, IMasterConnection connection, int cmdExecTimeout, bool isSelect);
    ~IEC104OutstandingCommand();

    bool isMatching(int typeId, int ca, int ioa);
    bool isSentFromConnection(IMasterConnection connection);
    bool hasTimedOut(uint64_t currentTime);
    bool isSelect();

    void sendActCon(bool negative);
    void sendActTerm(bool negative);

    int CA() {return m_ca;};
    int IOA() {return m_ioa;};
    int TypeId() {return m_typeId;};

private:

    CS101_ASDU m_receivedAsdu = nullptr;

    IMasterConnection m_connection = nullptr;

    int m_typeId = 0;
    int m_ca = 0;
    int m_ioa = 0;

    bool m_isSelect = false;

    int m_cmdExecTimeout = 0;

    uint64_t m_commandRcvdTime = 0;
    uint64_t m_nextTimeout = 0;

    int m_state = 0; /* 0 - idle/complete, 1 - waiting for ACT-CON, 2 - waiting for ACT-TERM */
};

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

    int ActConTimeout() {return m_actConTimeout;};
    int ActTermTimeout() {return m_actTermTimeout;};

    void ActConTimeout(int value) {m_actConTimeout = value;};
    void ActTermTimeout(int value) {m_actTermTimeout = value;};

    void registerControl(int (* operation)(char *operation, int paramCount, char* names[], char *parameters[], ControlDestination destination, ...));

    int operation(char *operation, int paramCount, char *names[], char *parameters[]);

private:

    std::vector<IEC104OutstandingCommand*> m_outstandingCommands;
    std::mutex m_outstandingCommandsLock;

    std::map<int, std::map<int, IEC104DataPoint*>> m_exchangeDefinitions;
    
    IEC104DataPoint* m_getDataPoint(int ca, int ioa, int typeId);
    void m_enqueueSpontDatapoint(IEC104DataPoint* dp, CS101_CauseOfTransmission cot, IEC60870_5_TypeID typeId);
    void m_updateDataPoint(IEC104DataPoint* dp, IEC60870_5_TypeID typeId, DatapointValue* value, CP56Time2a ts, uint8_t quality);

    bool checkIfSouthConnected();

    bool checkTimestamp(CP56Time2a timestamp);
    bool checkIfCmdTimeIsValid(int typeId, InformationObject io);
    void addToOutstandingCommands(CS101_ASDU asdu, IMasterConnection connection, bool isSelect);
    bool forwardCommand(CS101_ASDU asdu, InformationObject command, IMasterConnection connection);
    void removeOutstandingCommands(IMasterConnection connection);
    void removeAllOutstandingCommands();
    void handleActCon(int type, int ca, int ioa, bool isNegative);
    void handleActTerm(int type, int ca, int ioa, bool isNegative);
    bool requestSouthConnectionStatus();
    void updateSouthMonitoringInstance(Datapoint* dp, IEC104Config::SouthPluginMonitor* southPluginMonitor);

    static void printCP56Time2a(CP56Time2a time);
    static void rawMessageHandler(void* parameter, IMasterConnection connection,
                                  uint8_t* msg, int msgSize, bool sent);
    static bool clockSyncHandler(void* parameter, IMasterConnection connection,
                                 CS101_ASDU asdu, CP56Time2a newTime);

    void sendInterrogationResponse(IMasterConnection connection, CS101_ASDU asdu, int ca, int qoi);

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
    TLSConfiguration m_tlsConfig = nullptr;
    CS101_AppLayerParameters alParams = nullptr;
    IEC104Config* m_config = nullptr;

    int m_actConTimeout = 1000;
    int m_actTermTimeout = 1000;

    int (*m_oper)(char *operation, int paramCount, char* names[], char* parameters[], ControlDestination destination, ...) = nullptr;

    bool m_started = false;
    std::thread* m_monitoringThread = nullptr;
    void _monitoringThread();

    bool createTLSConfiguration();
};

#endif