/*
 * Fledge IEC 104 north plugin.
 *
 * Copyright (c) 2020, RTE (https://www.rte-france.com)
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Akli Rahmoun <akli.rahmoun at rte-france.com>
 */

#include <utils.h>
#include <config_category.h>
#include <reading.h>

#include <lib60870/hal_thread.h>
#include <lib60870/hal_time.h>

#include "iec104.h"
#include "iec104_utility.hpp"
#include "iec104_datapoint.hpp"


using namespace std;

static bool running = true;

IEC104Server::IEC104Server() :
    m_config(new IEC104Config())
{
}

IEC104Server::~IEC104Server()
{
    removeAllOutstandingCommands();

    stop();

    delete m_config;
}

IEC104DataPoint*
IEC104Server::m_getDataPoint(int ca, int ioa, int typeId)
{
    (void)typeId;

    IEC104DataPoint* dp = m_exchangeDefinitions[ca][ioa];

    if (dp) {
        if (dp->isMessageTypeMatching(typeId) == false)
            dp = nullptr;
    }

    return dp;
}

bool
IEC104Server::createTLSConfiguration()
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::createTLSConfiguration -";
    TLSConfiguration tlsConfig = TLSConfiguration_create();

    if (tlsConfig)
    {
        bool tlsConfigOk = true;

        string certificateStore = getDataDir() + string("/etc/certs/");
        string certificateStorePem = getDataDir() + string("/etc/certs/pem/");

        if (m_config->GetOwnCertificate().length() == 0 || m_config->GetPrivateKey().length() == 0) {
            Iec104Utility::log_error("%s No private key and/or certificate configured for client", beforeLog.c_str());
            tlsConfigOk = false;
        }

        if (m_config->GetOwnCertificate().empty() == false)
        {
            string ownCert = m_config->GetOwnCertificate();

            bool isPemOwnCertificate = ownCert.rfind(".pem") == ownCert.size() - 4;

            string ownCertFile;

            if(isPemOwnCertificate)
                ownCertFile = certificateStorePem + ownCert;
            else
                ownCertFile = certificateStore + ownCert;

            if (access(ownCertFile.c_str(), R_OK) == 0) {

                if (TLSConfiguration_setOwnCertificateFromFile(tlsConfig, ownCertFile.c_str()) == false) {
                    Iec104Utility::log_error("%s Failed to load own certificate from file: %s", beforeLog.c_str(), ownCertFile.c_str());
                    tlsConfigOk = false;
                }

            }
            else {
                Iec104Utility::log_error("%s Failed to access own certificate file: %s", beforeLog.c_str(), ownCertFile.c_str());
                tlsConfigOk = false;
            }
        }

        if (m_config->GetPrivateKey().empty() == false)
        {
            string privateKeyFile = certificateStore + m_config->GetPrivateKey();

            if (access(privateKeyFile.c_str(), R_OK) == 0) {

                if (TLSConfiguration_setOwnKeyFromFile(tlsConfig, privateKeyFile.c_str(), NULL) == false) {
                    Iec104Utility::log_error("%s Failed to load private key from file: %s", beforeLog.c_str(), privateKeyFile.c_str());
                    tlsConfigOk = false;
                }

            }
            else {
                Iec104Utility::log_error("%s Failed to access private key file: %s", beforeLog.c_str(), privateKeyFile.c_str());
                tlsConfigOk = false;
            }
        }

        if (m_config->GetRemoteCertificates().size() > 0) {
            TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

            for (std::string& remoteCert : m_config->GetRemoteCertificates())
            {
                bool isPemRemoteCertificate = remoteCert.rfind(".pem") == remoteCert.size() - 4;

                string remoteCertFile;

                if(isPemRemoteCertificate)
                    remoteCertFile = certificateStorePem + remoteCert;
                else
                    remoteCertFile = certificateStore + remoteCert;

                if (access(remoteCertFile.c_str(), R_OK) == 0) {
                    if (TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, remoteCertFile.c_str()) == false) {
                        Iec104Utility::log_warn("%s Failed to load remote certificate file: %s -> ignore certificate",
                                                beforeLog.c_str(), remoteCertFile.c_str());
                    }
                }
                else {
                    Iec104Utility::log_warn("%s Failed to access remote certificate file: %s -> ignore certificate", beforeLog.c_str(),
                                            remoteCertFile.c_str());
                }

            }
        }
        else {
            TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);
        }

        if (m_config->GetCaCertificates().size() > 0) {
            TLSConfiguration_setChainValidation(tlsConfig, true);

            for (std::string& caCert : m_config->GetCaCertificates())
            {
                bool isPemCaCertificate = caCert.rfind(".pem") == caCert.size() - 4;

                string caCertFile;

                if(isPemCaCertificate)
                    caCertFile = certificateStorePem + caCert;
                else
                    caCertFile = certificateStore + caCert;

                if (access(caCertFile.c_str(), R_OK) == 0) {
                    if (TLSConfiguration_addCACertificateFromFile(tlsConfig, caCertFile.c_str()) == false) {
                        Iec104Utility::log_warn("%s Failed to load CA certificate file: %s -> ignore certificate", beforeLog.c_str(),
                                                caCertFile.c_str());
                    }
                }
                else {
                    Iec104Utility::log_warn("%s Failed to access CA certificate file: %s -> ignore certificate", beforeLog.c_str(),
                                            caCertFile.c_str());
                }

            }
        }
        else {
            TLSConfiguration_setChainValidation(tlsConfig, false);
        }

        if (tlsConfigOk) {
            m_tlsConfig = tlsConfig;
        }
        else {
            TLSConfiguration_destroy(tlsConfig);
            m_tlsConfig = nullptr;
        }

        return tlsConfigOk;
    }
    else {
        return false;
    }
}

void
IEC104Server::setJsonConfig(const std::string& stackConfig,
                                const std::string& dataExchangeConfig,
                                const std::string& tlsConfig)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::setJsonConfig -";
    m_config->importExchangeConfig(dataExchangeConfig);
    m_config->importProtocolConfig(stackConfig);
    m_config->importTlsConfig(tlsConfig);

    m_exchangeDefinitions = *m_config->getExchangeDefinitions();

    if (m_config->UseTLS()) {
        if (createTLSConfiguration()) {
            m_slave = CS104_Slave_createSecure(m_config->AsduQueueSize(), 100, m_tlsConfig);
        }
    }
    else {
       m_slave = CS104_Slave_create(m_config->AsduQueueSize(), 100);
    }

    if (m_slave)
    {
        CS104_Slave_setLocalPort(m_slave, m_config->TcpPort());

        Iec104Utility::log_info("%s TCP/IP parameters:", beforeLog.c_str()); //LCOV_EXCL_LINE
        Iec104Utility::log_info("%s  TCP port: %i", beforeLog.c_str(), m_config->TcpPort()); //LCOV_EXCL_LINE

        if (m_config->bindOnIp()) {
            CS104_Slave_setLocalAddress(m_slave, m_config->GetLocalIP());
            Iec104Utility::log_info("%s  IP address: %s", beforeLog.c_str(), m_config->GetLocalIP()); //LCOV_EXCL_LINE
        }

        CS104_APCIParameters apciParams =
            CS104_Slave_getConnectionParameters(m_slave);

        apciParams->k = m_config->K();
        apciParams->w = m_config->W();
        apciParams->t0 = m_config->T0();
        apciParams->t1 = m_config->T1();
        apciParams->t2 = m_config->T2();
        apciParams->t3 = m_config->T3();

        Iec104Utility::log_info("%s APCI parameters:", beforeLog.c_str());
        Iec104Utility::log_info("%s  t0: %i", beforeLog.c_str(), apciParams->t0); //LCOV_EXCL_LINE
        Iec104Utility::log_info("%s  t1: %i", beforeLog.c_str(), apciParams->t1); //LCOV_EXCL_LINE
        Iec104Utility::log_info("%s  t2: %i", beforeLog.c_str(), apciParams->t2); //LCOV_EXCL_LINE
        Iec104Utility::log_info("%s  t3: %i", beforeLog.c_str(), apciParams->t3); //LCOV_EXCL_LINE
        Iec104Utility::log_info("%s  k: %i", beforeLog.c_str(), apciParams->k); //LCOV_EXCL_LINE
        Iec104Utility::log_info("%s  w: %i", beforeLog.c_str(), apciParams->w); //LCOV_EXCL_LINE

        CS101_AppLayerParameters appLayerParams =
            CS104_Slave_getAppLayerParameters(m_slave);

        if (m_config->AsduSize() == 0)
            appLayerParams->maxSizeOfASDU = 253;
        else
            appLayerParams->maxSizeOfASDU = m_config->AsduSize();

        appLayerParams->sizeOfCA = m_config->CaSize();
        appLayerParams->sizeOfIOA = m_config->IOASize();

        /* set the callback handler for the clock synchronization command */
        CS104_Slave_setClockSyncHandler(m_slave, clockSyncHandler, this);

        /* set the callback handler for the interrogation command */
        CS104_Slave_setInterrogationHandler(m_slave, interrogationHandler, this);

        /* set handler for other message types */
        CS104_Slave_setASDUHandler(m_slave, asduHandler, this);

        /* set handler to handle connection requests */
        CS104_Slave_setConnectionRequestHandler(m_slave, connectionRequestHandler, this);

        /* set handler to track connection events */
        CS104_Slave_setConnectionEventHandler(m_slave, connectionEventHandler, this);

        auto redGroups = m_config->getRedGroups();

        if (redGroups.empty()) {
            CS104_Slave_setServerMode(m_slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);
        }
        else {
            CS104_Slave_setServerMode(m_slave, CS104_MODE_MULTIPLE_REDUNDANCY_GROUPS);

            for (CS104_RedundancyGroup redGroup : redGroups) {
                CS104_Slave_addRedundancyGroup(m_slave, redGroup);
            }
        }

        m_started = true;
        m_monitoringThread = new std::thread(&IEC104Server::_monitoringThread, this);

        Iec104Utility::log_info("%s CS104 server initialized", beforeLog.c_str()); //LCOV_EXCL_LINE
    }
    else {
        Iec104Utility::log_error("%s Failed to create CS104 server instance", beforeLog.c_str()); //LCOV_EXCL_LINE
    }
}

/**
 *
 * @param conf	Fledge configuration category
 */
void
IEC104Server::configure(const ConfigCategory* config)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::configure -";
    Iec104Utility::log_info("%s configure called", beforeLog.c_str()); //LCOV_EXCL_LINE

    if (config->itemExists("name"))
        m_name = config->getValue("name"); //LCOV_EXCL_LINE
    else
        Iec104Utility::log_error("%s Missing name in configuration", beforeLog.c_str()); //LCOV_EXCL_LINE

    if (config->itemExists("protocol_stack") == false) {
        Iec104Utility::log_error("%s Missing protocol configuration", beforeLog.c_str()); //LCOV_EXCL_LINE
        return;
    }

    if (config->itemExists("exchanged_data") == false) {
        Iec104Utility::log_error("%s Missing exchange data configuration", beforeLog.c_str()); //LCOV_EXCL_LINE
        return;
    }

    const std::string protocolStack = config->getValue("protocol_stack");

    const std::string dataExchange = config->getValue("exchanged_data");

    std::string tlsConfig = "";

    if (config->itemExists("tls_conf") == false) {
        Iec104Utility::log_error("%s Missing TLS configuration", beforeLog.c_str()); //LCOV_EXCL_LINE
    }
    else {
        tlsConfig = config->getValue("tls_conf");
    }

    setJsonConfig(protocolStack, dataExchange, tlsConfig);
}

void
IEC104Server::registerControl(int (* operation)(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...))
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::registerControl -";

    m_oper = operation;

    Iec104Utility::log_warn("%s RegisterControl is called", beforeLog.c_str()); //LCOV_EXCL_LINE
}

bool
IEC104Server::requestSouthConnectionStatus()
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::requestSouthConnectionStatus -";
    if (m_oper) {
        Iec104Utility::log_warn("%s Send request_connection_status operation", beforeLog.c_str()); //LCOV_EXCL_LINE

        char* parameters[1];
        char* names[1];

        names[0] = (char*)"desc";

        parameters[0] = (char*)"request connection status";

        if (m_config->CmdDest() == "")
            m_oper((char*)"request_connection_status", 1, names, parameters, DestinationBroadcast, nullptr);
        else
            m_oper((char*)"request_connection_status", 1, names, parameters, DestinationService, m_config->CmdDest().c_str());

        return true;
    }
    else {
        Iec104Utility::log_warn("%s m_oper not set -> call registerControl", beforeLog.c_str());

        return false;
    }
}

void
IEC104Server::_monitoringThread()
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::_monitoringThread -";
    bool southStatusRequested = false;

    bool serverRunning = false;

    while (m_started)
    {
        if (southStatusRequested == false) {
            southStatusRequested = requestSouthConnectionStatus();
        }

        if (m_config->GetMode() == IEC104Config::Mode::CONNECT_ALWAYS) {
            if (serverRunning == false) {
                CS104_Slave_start(m_slave);
                Iec104Utility::log_warn("%s Server started - mode: CONNECT_ALWAYS", beforeLog.c_str()); //LCOV_EXCL_LINE
                serverRunning = true;//LCOV_EXCL_LINE
            }
        }
        else if (m_config->GetMode() == IEC104Config::Mode::CONNECT_IF_SOUTH_CONNX_STARTED) {
            if (serverRunning == false) {

                if (checkIfSouthConnected()) {
                    Iec104Utility::log_warn("%s Server started - mode: CONNECT_IF_SOUTH_CONNX_STARTED", beforeLog.c_str()); //LCOV_EXCL_LINE
                    CS104_Slave_start(m_slave);
                    serverRunning = true;//LCOV_EXCL_LINE
                }
            }
            else {
                if (checkIfSouthConnected() == false) {
                    Iec104Utility::log_warn("%s Server stopped - mode: CONNECT_IF_SOUTH_CONNX_STARTED", beforeLog.c_str()); //LCOV_EXCL_LINE
                    CS104_Slave_stop(m_slave);
                    serverRunning = false;//LCOV_EXCL_LINE
                }
            }
        }

        /* check timeouts for outstanding commands */
        m_outstandingCommandsLock.lock();

        std::vector<IEC104OutstandingCommand*>::iterator it;

        uint64_t currentTime = Hal_getTimeInMs();

        for (it = m_outstandingCommands.begin(); it != m_outstandingCommands.end();)
        {
            IEC104OutstandingCommand* outstandingCommand = *it;

            if (outstandingCommand->hasTimedOut(currentTime)) {
                Iec104Utility::log_warn("%s command %i:%i (type: %i) timeout", beforeLog.c_str(), outstandingCommand->CA(), outstandingCommand->IOA(), outstandingCommand->TypeId()); //LCOV_EXCL_LINE

                it = m_outstandingCommands.erase(it);

                delete outstandingCommand;
            }
            else {
                it++;
            }
        }

        m_outstandingCommandsLock.unlock();

        Thread_sleep(100);
    }

    if (serverRunning) {
        CS104_Slave_stop(m_slave);
        serverRunning = false;
    }
}

static void
setTimestamp(CP56Time2a destTime, CP56Time2a srcTime)
{
    if (srcTime) {
        memcpy(destTime, srcTime, sizeof(struct sCP56Time2a));
    }
    else {
        CP56Time2a_createFromMsTimestamp(destTime, Hal_getTimeInMs());
    }
}

void
IEC104Server::m_updateDataPoint(IEC104DataPoint* dp, IEC60870_5_TypeID typeId, DatapointValue* value, CP56Time2a ts, uint8_t quality)
{
    switch (typeId) {
        case M_SP_NA_1:
        case M_SP_TB_1:
            {
                if (value && (value->getType() == DatapointValue::dataTagType::T_INTEGER)) {
                    dp->m_value.sp.value = (unsigned int)value->toInt();
                }

                dp->m_value.sp.quality = quality;

                if (typeId == M_SP_TB_1) {
                    setTimestamp(&(dp->m_ts), ts);
                }
            }

            break; //LCOV_EXCL_LINE

        case M_DP_NA_1:
        case M_DP_TB_1:
            {
                if (value && (value->getType() == DatapointValue::dataTagType::T_INTEGER)) {
                    dp->m_value.dp.value = (unsigned int)value->toInt();
                }

                dp->m_value.dp.quality = quality;

                if (typeId == M_DP_TB_1) {
                    setTimestamp(&(dp->m_ts), ts);
                }
            }

            break; //LCOV_EXCL_LINE

        case M_ST_NA_1:
        case M_ST_TB_1:
            {
                if (value && (value->getType() == DatapointValue::dataTagType::T_INTEGER)) {
                    dp->m_value.stepPos.posValue = (int)(value->toInt() & 0x7f);
                    dp->m_value.stepPos.transient = (unsigned int)((value->toInt() & 0x80) != 0);
                }

                dp->m_value.stepPos.quality = quality;

                if (typeId == M_ST_TB_1) {
                    setTimestamp(&(dp->m_ts), ts);
                }
            }
            break; //LCOV_EXCL_LINE

        case M_ME_NA_1: /* normalized value */
        case M_ME_TD_1:
            {
                if (value && (value->getType() == DatapointValue::dataTagType::T_FLOAT)) {
                    dp->m_value.mv_normalized.value = (float)value->toDouble();
                }

                dp->m_value.mv_normalized.quality = quality;

                if (typeId == M_ME_TD_1) {
                    setTimestamp(&(dp->m_ts), ts);
                }
            }

            break; //LCOV_EXCL_LINE

        case M_ME_NB_1: /* scaled value */
        case M_ME_TE_1:
            {
                if (value && (value->getType() == DatapointValue::dataTagType::T_INTEGER)) {
                    dp->m_value.mv_scaled.value = (unsigned int)value->toInt();
                }

                dp->m_value.mv_scaled.quality = quality;

                if (typeId == M_ME_TE_1) {
                    setTimestamp(&(dp->m_ts), ts);
                }
            }

            break; //LCOV_EXCL_LINE

        case M_ME_NC_1: /* short float value */
        case M_ME_TF_1:
            {
                if (value && (value->getType() == DatapointValue::dataTagType::T_FLOAT)) {
                    dp->m_value.mv_short.value = (float)value->toDouble();
                }

                dp->m_value.mv_short.quality = quality;

                if (typeId == M_ME_TF_1) {
                    setTimestamp(&(dp->m_ts), ts);
                }
            }

            break; //LCOV_EXCL_LINE

    }
}

void
IEC104Server::m_enqueueSpontDatapoint(IEC104DataPoint* dp, CS101_CauseOfTransmission cot, IEC60870_5_TypeID typeId)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::m_enqueueSpontDatapoint -";
    CS101_ASDU asdu = CS101_ASDU_create(CS104_Slave_getAppLayerParameters(m_slave), false, cot, 0, dp->m_ca, false, false);

    if (asdu)
    {
        InformationObject io = NULL;

        switch (typeId) {

            case M_SP_NA_1:
                {
                    io = (InformationObject)SinglePointInformation_create(NULL, dp->m_ioa, dp->m_value.sp.value, dp->m_value.sp.quality);
                }
                break; //LCOV_EXCL_LINE

            case M_SP_TB_1:
                {
                    io = (InformationObject)SinglePointWithCP56Time2a_create(NULL, dp->m_ioa, dp->m_value.sp.value, dp->m_value.sp.quality, &(dp->m_ts));
                }
                break; //LCOV_EXCL_LINE

            case M_DP_NA_1:
                {
                    io = (InformationObject)DoublePointInformation_create(NULL, dp->m_ioa, (DoublePointValue)dp->m_value.dp.value, dp->m_value.dp.quality);
                }
                break; //LCOV_EXCL_LINE

            case M_DP_TB_1:
                {
                    io = (InformationObject)DoublePointWithCP56Time2a_create(NULL, dp->m_ioa, (DoublePointValue)dp->m_value.dp.value, dp->m_value.dp.quality, &(dp->m_ts));
                }
                break; //LCOV_EXCL_LINE

            case M_ST_NA_1:
                {
                    io = (InformationObject)StepPositionInformation_create(NULL, dp->m_ioa, dp->m_value.stepPos.posValue, dp->m_value.stepPos.transient, dp->m_value.stepPos.quality);
                }
                break; //LCOV_EXCL_LINE

            case M_ST_TB_1:
                {
                    io = (InformationObject)StepPositionWithCP56Time2a_create(NULL, dp->m_ioa, dp->m_value.stepPos.posValue, dp->m_value.stepPos.transient, dp->m_value.stepPos.quality, &(dp->m_ts));
                }
                break; //LCOV_EXCL_LINE

            case M_ME_NA_1:
                {
                    io = (InformationObject)MeasuredValueNormalized_create(NULL, dp->m_ioa, dp->m_value.mv_normalized.value, dp->m_value.mv_normalized.quality);
                }
                break; //LCOV_EXCL_LINE

             case M_ME_TD_1:
                {
                    io = (InformationObject)MeasuredValueNormalizedWithCP56Time2a_create(NULL, dp->m_ioa, dp->m_value.mv_normalized.value, dp->m_value.mv_normalized.quality, &(dp->m_ts));
                }
                break; //LCOV_EXCL_LINE

            case M_ME_NB_1:
                {
                    io = (InformationObject)MeasuredValueScaled_create(NULL, dp->m_ioa, dp->m_value.mv_scaled.value, dp->m_value.mv_scaled.quality);
                }
                break; //LCOV_EXCL_LINE

            case M_ME_TE_1:
                {
                    io = (InformationObject)MeasuredValueScaledWithCP56Time2a_create(NULL, dp->m_ioa, dp->m_value.mv_scaled.value, dp->m_value.mv_scaled.quality, &(dp->m_ts));
                }
                break; //LCOV_EXCL_LINE

            case M_ME_NC_1:
                {
                    io = (InformationObject)MeasuredValueShort_create(NULL, dp->m_ioa, dp->m_value.mv_short.value, dp->m_value.mv_short.quality);
                }
                break; //LCOV_EXCL_LINE

            case M_ME_TF_1:
                {
                    io = (InformationObject)MeasuredValueShortWithCP56Time2a_create(NULL, dp->m_ioa, dp->m_value.mv_short.value, dp->m_value.mv_short.quality, &(dp->m_ts));
                }
                break; //LCOV_EXCL_LINE

            default:
                Iec104Utility::log_error("%s Unsupported type ID %i", beforeLog.c_str(), typeId);

                break; //LCOV_EXCL_LINE
        }

        if (io) {
            CS101_ASDU_addInformationObject(asdu, io);

            CS104_Slave_enqueueASDU(m_slave, asdu);

            InformationObject_destroy(io);
        }

        CS101_ASDU_destroy(asdu);
    }
}

bool
IEC104Server::checkIfSouthConnected()
{
    bool connected = false;

    for (auto southPlugin : m_config->GetMonitoredSouthPlugins())
    {
        if (southPlugin->GetConnxStatus() == IEC104Config::ConnectionStatus::STARTED) {
            connected = true;
            break; //LCOV_EXCL_LINE
        }
    }

    return connected;
}

bool
IEC104Server::checkTimestamp(CP56Time2a timestamp)
{
    uint64_t currentTime = Hal_getTimeInMs();

    uint64_t commandTime = CP56Time2a_toMsTimestamp(timestamp);

    int timeDiff;

    if (commandTime > currentTime) {
        timeDiff = (int)(commandTime - currentTime);
    }
    else {
        timeDiff = (int)(currentTime - commandTime);
    }

    if ((timeDiff > (m_config->CmdRecvTimeout() * 1000)) || (timeDiff < 0)) {
        return false;
    }
    else {
        return true;
    }
}

void
IEC104Server::addToOutstandingCommands(CS101_ASDU asdu, IMasterConnection connection, bool isSelect)
{
    m_outstandingCommandsLock.lock();

    IEC104OutstandingCommand* outstandingCommand = new IEC104OutstandingCommand(asdu, connection, m_config->CmdExecTimeout(), isSelect);

    m_outstandingCommands.push_back(outstandingCommand);

    m_outstandingCommandsLock.unlock();
}

void
IEC104Server::removeOutstandingCommands(IMasterConnection connection)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::removeOutstandingCommands -";
    m_outstandingCommandsLock.lock();

    std::vector<IEC104OutstandingCommand*>::iterator it;

    for (it = m_outstandingCommands.begin(); it != m_outstandingCommands.end();)
    {
        IEC104OutstandingCommand* outstandingCommand = *it;

        if (outstandingCommand->isSentFromConnection(connection))
        {
            Iec104Utility::log_warn("%s Remove outstanding command to %i:%i while waiting for feedback", beforeLog.c_str(),
                                    outstandingCommand->CA(), outstandingCommand->IOA()); //LCOV_EXCL_LINE

            it = m_outstandingCommands.erase(it);

            delete outstandingCommand;
        }
        else
        {
            it++;
        }
    }

    m_outstandingCommandsLock.unlock();
}

void
IEC104Server::removeAllOutstandingCommands()
{
    m_outstandingCommandsLock.lock();

    std::vector<IEC104OutstandingCommand*>::iterator it;

    for (it = m_outstandingCommands.begin(); it != m_outstandingCommands.end();)
    {
        IEC104OutstandingCommand* outstandingCommand = *it;

        delete outstandingCommand;

        it = m_outstandingCommands.erase(it);
    }

    m_outstandingCommandsLock.unlock();
}

void
IEC104Server::handleActCon(int type, int ca, int ioa, bool isNegative)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::handleActCon -";
    m_outstandingCommandsLock.lock();

    std::vector<IEC104OutstandingCommand*>::iterator it;

    for (it = m_outstandingCommands.begin(); it != m_outstandingCommands.end(); it++)
    {
        IEC104OutstandingCommand* outstandingCommand = *it;

        if (outstandingCommand->isMatching(type, ca, ioa)) {
            outstandingCommand->sendActCon(isNegative);

            if (outstandingCommand->isSelect()) {
                m_outstandingCommands.erase(it);

                Iec104Utility::log_info("%s Outstanding command %i:%i sent ACT-CON(select) -> remove", beforeLog.c_str(),
                                        outstandingCommand->CA(), outstandingCommand->IOA()); //LCOV_EXCL_LINE

                delete outstandingCommand;
            }

            break; //LCOV_EXCL_LINE
        }
    }

    m_outstandingCommandsLock.unlock();
}

void
IEC104Server::handleActTerm(int type, int ca, int ioa, bool isNegative)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::handleActTerm -";
    m_outstandingCommandsLock.lock();

    std::vector<IEC104OutstandingCommand*>::iterator it;

    for (it = m_outstandingCommands.begin(); it != m_outstandingCommands.end(); it++)
    {
        IEC104OutstandingCommand* outstandingCommand = *it;

        if (outstandingCommand->isMatching(type, ca, ioa))
        {
            outstandingCommand->sendActTerm(isNegative);

            Iec104Utility::log_info("%s Outstanding command %i:%i sent ACT-TERM -> remove", beforeLog.c_str(),
                                    outstandingCommand->CA(), outstandingCommand->IOA()); //LCOV_EXCL_LINE

            m_outstandingCommands.erase(it);

            delete outstandingCommand;

            break; //LCOV_EXCL_LINE
        }
    }

    m_outstandingCommandsLock.unlock();
}

enum CommandParameters{
    TYPE,
    CA,
    IOA,
    COT,
    NEGATIVE,
    SE,
    TEST,
    TS,
    VALUE
};

bool
IEC104Server::forwardCommand(CS101_ASDU asdu, InformationObject command, IMasterConnection connection)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::forwardCommand -";
    if (!m_oper) {
        Iec104Utility::log_error("%s No operation function available", beforeLog.c_str());
        return false;
    }
    else {
        IEC60870_5_TypeID typeId = CS101_ASDU_getTypeID(asdu);

        int parameterCount = 9;

        std::string typeStr = IEC104DataPoint::getStringFromTypeID(typeId);
        std::string caStr = std::to_string(CS101_ASDU_getCA(asdu));
        std::string ioaStr = std::to_string(InformationObject_getObjectAddress(command));
        std::string cotStr = std::to_string(CS101_ASDU_getCOT(asdu));
        std::string testStr = std::to_string(CS101_ASDU_isTest(asdu) ? 1 : 0);
        std::string negativeStr = std::to_string(CS101_ASDU_isNegative(asdu) ? 1 : 0);

        char* s_type = (char*) typeStr.c_str();
        char* s_ca = (char*)caStr.c_str();
        char* s_ioa = (char*)ioaStr.c_str();
        char* s_cot = (char*)cotStr.c_str();
        char* s_test = (char*)testStr.c_str();
        char* s_negative = (char*)negativeStr.c_str();
        char* s_val = NULL;
        char* s_select = (char*) "0";
        char* s_ts = (char*) "";

        char* parameters[parameterCount];
        char* names[parameterCount];

        names[TYPE] = (char*)"co_type";
        names[CA] = (char*)"co_ca";
        names[IOA] = (char*)"co_ioa";
        names[COT] = (char*)"co_cot";
        names[NEGATIVE] = (char*)"co_negative";
        names[SE] = (char*)"co_se";
        names[TEST] = (char*)"co_test";
        names[TS] = (char*)"co_ts";
        names[VALUE] = (char*)"co_value";

        parameters[TYPE] = s_type;
        parameters[CA] = s_ca;
        parameters[IOA] = s_ioa;
        parameters[COT] = s_cot;
        parameters[NEGATIVE] = s_negative;
        parameters[SE] = s_select;
        parameters[TEST] = s_test;
        parameters[TS] = s_ts;

        switch (typeId) {

            case C_SC_NA_1:
                {
                    parameters[0] = (char*)"C_SC_NA_1";

                    SingleCommand sc = (SingleCommand)command;

                    s_val = (char*)(SingleCommand_getState(sc) ? "1" : "0");
                    s_select = (char*)(SingleCommand_isSelect(sc) ? "1" : "0");

                    parameters[VALUE] = s_val;
                    parameters[SE] = s_select;

                    addToOutstandingCommands(asdu, connection, SingleCommand_isSelect(sc));

                    Iec104Utility::log_info("%s Send single command (%s)", beforeLog.c_str(),
                                            SingleCommand_isSelect(sc) ? "select" : "execute"); //LCOV_EXCL_LINE

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break; //LCOV_EXCL_LINE

            case C_SC_TA_1:
                {
                    SingleCommandWithCP56Time2a sc = (SingleCommandWithCP56Time2a)command;

                    s_val = (char*)(SingleCommand_getState((SingleCommand)sc) ? "1" : "0");
                    s_select = (char*)(SingleCommand_isSelect((SingleCommand)sc) ? "1" : "0");

                    CP56Time2a timestamp = SingleCommandWithCP56Time2a_getTimestamp(sc);

                    uint64_t msTimeStamp = CP56Time2a_toMsTimestamp(timestamp);

                    parameters[TS] = (char*)(std::to_string(msTimeStamp).c_str());

                    parameters[VALUE] = s_val;
                    parameters[SE] = s_select;

                    addToOutstandingCommands(asdu, connection, SingleCommand_isSelect((SingleCommand)sc));

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break; //LCOV_EXCL_LINE

            case C_DC_NA_1:
                {
                    DoubleCommand dc = (DoubleCommand)command;

                    s_val = (char*)std::to_string(DoubleCommand_getState(dc)).c_str();
                    s_select = (char*)(DoubleCommand_isSelect(dc) ? "1" : "0");

                    parameters[VALUE] = s_val;
                    parameters[SE] = s_select;

                    addToOutstandingCommands(asdu, connection, DoubleCommand_isSelect(dc));

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, DestinationService, m_config->CmdDest().c_str());
                }
                break; //LCOV_EXCL_LINE

            case C_DC_TA_1:
                {
                    DoubleCommandWithCP56Time2a dc = (DoubleCommandWithCP56Time2a)command;

                    s_val = (char*)std::to_string(DoubleCommand_getState((DoubleCommand)dc)).c_str();
                    s_select = (char*)(DoubleCommand_isSelect((DoubleCommand)dc) ? "1" : "0");

                    CP56Time2a timestamp = DoubleCommandWithCP56Time2a_getTimestamp(dc);

                    uint64_t msTimeStamp = CP56Time2a_toMsTimestamp(timestamp);

                    parameters[TS] = (char*)(std::to_string(msTimeStamp).c_str());

                    parameters[VALUE] = s_val;
                    parameters[SE] = s_select;

                    addToOutstandingCommands(asdu, connection, DoubleCommand_isSelect((DoubleCommand)dc));

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break; //LCOV_EXCL_LINE

            case C_RC_NA_1:
                {
                    StepCommand rc = (StepCommand)command;

                    s_val = (char*)std::to_string(StepCommand_getState(rc)).c_str();
                    s_select = (char*)(StepCommand_isSelect(rc) ? "1" : "0");

                    parameters[VALUE] = s_val;
                    parameters[SE] = s_select;

                    addToOutstandingCommands(asdu, connection, StepCommand_isSelect(rc));

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break; //LCOV_EXCL_LINE

             case C_RC_TA_1:
                {
                    StepCommandWithCP56Time2a rc = (StepCommandWithCP56Time2a)command;

                    s_val = (char*)std::to_string(StepCommand_getState((StepCommand)rc)).c_str();
                    s_select = (char*)(StepCommand_isSelect((StepCommand)rc) ? "1" : "0");

                    CP56Time2a timestamp = StepCommandWithCP56Time2a_getTimestamp(rc);

                    uint64_t msTimeStamp = CP56Time2a_toMsTimestamp(timestamp);

                    parameters[TS] = (char*)(std::to_string(msTimeStamp).c_str());

                    parameters[VALUE] = s_val;
                    parameters[SE] = s_select;

                    addToOutstandingCommands(asdu, connection, StepCommand_isSelect((StepCommand)rc));

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break; //LCOV_EXCL_LINE

            case C_SE_NA_1:
                {
                    SetpointCommandNormalized spn = (SetpointCommandNormalized)command;

                    s_val = (char*)(std::to_string(SetpointCommandNormalized_getValue(spn)).c_str());

                    parameters[VALUE] = s_val;

                    addToOutstandingCommands(asdu, connection, false);

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break;

            case C_SE_TA_1:
                {
                    SetpointCommandNormalizedWithCP56Time2a spn = (SetpointCommandNormalizedWithCP56Time2a)command;

                    s_val = (char*)(std::to_string(SetpointCommandNormalized_getValue((SetpointCommandNormalized)spn)).c_str());

                    CP56Time2a timestamp = SetpointCommandNormalizedWithCP56Time2a_getTimestamp(spn);

                    uint64_t msTimeStamp = CP56Time2a_toMsTimestamp(timestamp);

                    parameters[TS] = (char*)(std::to_string(msTimeStamp).c_str());

                    parameters[VALUE] = s_val;

                    addToOutstandingCommands(asdu, connection, false);

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break; //LCOV_EXCL_LINE

            case C_SE_NB_1:
                {
                    SetpointCommandScaled sps = (SetpointCommandScaled)command;

                    s_val = (char*)(std::to_string(SetpointCommandScaled_getValue(sps)).c_str());

                    parameters[VALUE] = s_val;

                    addToOutstandingCommands(asdu, connection, false);

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break; //LCOV_EXCL_LINE

            case C_SE_TB_1:
                {
                    SetpointCommandScaledWithCP56Time2a sps = (SetpointCommandScaledWithCP56Time2a)command;

                    s_val = (char*)(std::to_string(SetpointCommandScaled_getValue((SetpointCommandScaled)sps)).c_str());

                    CP56Time2a timestamp = SetpointCommandScaledWithCP56Time2a_getTimestamp(sps);

                    uint64_t msTimeStamp = CP56Time2a_toMsTimestamp(timestamp);

                    parameters[TS] = (char*)(std::to_string(msTimeStamp).c_str());

                    parameters[VALUE] = s_val;

                    addToOutstandingCommands(asdu, connection, false);

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break; //LCOV_EXCL_LINE

            case C_SE_NC_1:
                {
                    SetpointCommandShort spf = (SetpointCommandShort)command;

                    s_val = (char*)(std::to_string(SetpointCommandShort_getValue(spf)).c_str());

                    parameters[VALUE] = s_val;

                    addToOutstandingCommands(asdu, connection, false);

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break;

            case C_SE_TC_1:
                {
                    SetpointCommandShortWithCP56Time2a spf = (SetpointCommandShortWithCP56Time2a)command;

                    s_val = (char*)(std::to_string(SetpointCommandShort_getValue((SetpointCommandShort)spf)).c_str());

                    CP56Time2a timestamp = SetpointCommandShortWithCP56Time2a_getTimestamp(spf);

                    uint64_t msTimeStamp = CP56Time2a_toMsTimestamp(timestamp);

                    parameters[TS] = (char*)(std::to_string(msTimeStamp).c_str());

                    parameters[VALUE] = s_val;

                    addToOutstandingCommands(asdu, connection, false);

                    if (m_config->CmdDest() == "")
                        m_oper((char*)"IEC104Command", parameterCount, names, parameters, DestinationBroadcast, NULL);
                    else
                        m_oper((char*) "IEC104Command", parameterCount, names, parameters, DestinationService, m_config->CmdDest().c_str());
                }
                break; //LCOV_EXCL_LINE

            default:

                Iec104Utility::log_error("%s Unsupported command type", beforeLog.c_str());

                return false;
        }

        return true;
    }
}

void
IEC104Server::updateSouthMonitoringInstance(Datapoint* dp, IEC104Config::SouthPluginMonitor* southPluginMonitor)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::updateSouthMonitoringInstance -";
    DatapointValue dpv = dp->getData();

    vector<Datapoint*>* sdp = dpv.getDpVec();

    for (Datapoint* objDp : *sdp)
    {
        DatapointValue attrVal = objDp->getData();

        if (objDp->getName() == "connx_status") {
            std::string connxStatusValue = attrVal.toStringValue();

            IEC104Config::ConnectionStatus connxStatus = IEC104Config::ConnectionStatus::NOT_CONNECTED;

            if (connxStatusValue == "not connected") {
                connxStatus = IEC104Config::ConnectionStatus::NOT_CONNECTED; //LCOV_EXCL_LINE
            }
            else if (connxStatusValue == "started") {
                connxStatus = IEC104Config::ConnectionStatus::STARTED;
            }

            Iec104Utility::log_warn("%s south connection status for %s changed to %s", beforeLog.c_str(),
                                    southPluginMonitor->GetAssetName().c_str(), connxStatusValue.c_str()); //LCOV_EXCL_LINE

            southPluginMonitor->SetConnxStatus(connxStatus);
        }
        else if (objDp->getName() == "gi_status") {
            std::string giStatusValue = attrVal.toStringValue();

            IEC104Config::GiStatus giStatus = IEC104Config::GiStatus::IDLE;

            if (giStatusValue ==  "started") {
                giStatus = IEC104Config::GiStatus::STARTED;//LCOV_EXCL_LINE
            }
            else if (giStatusValue == "in progress") {
                giStatus = IEC104Config::GiStatus::IN_PROGRESS;//LCOV_EXCL_LINE
            }
            else if (giStatusValue == "failed") {
                giStatus = IEC104Config::GiStatus::FAILED;//LCOV_EXCL_LINE
            }
            else if (giStatusValue == "finished") {
                giStatus = IEC104Config::GiStatus::FINISHED;//LCOV_EXCL_LINE
            }

            Iec104Utility::log_warn("%s south gi status for %s changed to %s", beforeLog.c_str(),
                                    southPluginMonitor->GetAssetName().c_str(), giStatusValue.c_str()); //LCOV_EXCL_LINE

            southPluginMonitor->SetGiStatus(giStatus);
        }
    }
}

/**
 * Send a block of reading to IEC104 Server
 *
 * @param readings	The readings to send
 * @return 		The number of readings sent
 */
uint32_t
IEC104Server::send(const vector<Reading*>& readings)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::send -";
    int n = 0;

    int readingsSent = 0;

    for (auto reading = readings.cbegin(); reading != readings.cend(); reading++)
    {
        vector<Datapoint*>& dataPoints = (*reading)->getReadingData();
        string assetName = (*reading)->getAssetName();

        for (Datapoint* dp : dataPoints) {

            if (dp->getName() == "south_event") {

                Iec104Utility::log_warn("%s Receive south_event", beforeLog.c_str()); //LCOV_EXCL_LINE

                // check if we know the south plugin
                for (auto southPluginMonitor : m_config->GetMonitoredSouthPlugins()) {
                    if (assetName == southPluginMonitor->GetAssetName()) {

                        Iec104Utility::log_warn("%s Found matching monitored plugin for south_event", beforeLog.c_str()); //LCOV_EXCL_LINE

                        updateSouthMonitoringInstance(dp, southPluginMonitor);

                        readingsSent++;

                        break; //LCOV_EXCL_LINE
                    }
                }
            }
            else if (dp->getName() == "data_object")
            {
                readingsSent++;

                if (CS104_Slave_isRunning(m_slave) == false) {
                    Iec104Utility::log_warn("%s Failed to send data: server not running", beforeLog.c_str());
                    continue;
                }

                int ca = -1;
                int ioa = -1;
                CS101_CauseOfTransmission cot = CS101_COT_UNKNOWN_COT;
                int type = -1;

                DatapointValue dpv = dp->getData();

                vector<Datapoint*>* sdp = dpv.getDpVec();

                bool hasTimestamp = false;
                uint64_t timestamp = 0;
                bool ts_iv = false;
                bool ts_su = false;
                bool ts_sub = false;

                bool isNegative = false;

                DatapointValue* value = nullptr;

                uint8_t qd = IEC60870_QUALITY_GOOD;

                for (Datapoint* objDp : *sdp)
                {
                    DatapointValue attrVal = objDp->getData();

                    if (objDp->getName() == "do_ca") {
                        ca = attrVal.toInt();
                    }
                    else if (objDp->getName() == "do_ioa") {
                        ioa = attrVal.toInt();
                    }
                    else if (objDp->getName() == "do_cot") {
                        cot = (CS101_CauseOfTransmission)attrVal.toInt();
                    }
                    else if (objDp->getName() == "do_type") {
                        type = IEC104DataPoint::getTypeIdFromString(attrVal.toStringValue());
                        Iec104Utility::log_debug("%s TYPE: %s (%i)", attrVal.toStringValue().c_str(), beforeLog.c_str(), type); //LCOV_EXCL_LINE
                    }
                    else if (objDp->getName() == "do_value") {
                        value = new DatapointValue(attrVal);
                    }
                    else if (objDp->getName() == "do_negative") {
                        if (attrVal.toInt() != 0)
                            isNegative = true;
                    }
                    else if (objDp->getName() == "do_quality_iv") {
                        if (attrVal.toInt() != 0)
                            qd |= IEC60870_QUALITY_INVALID;
                    }
                    else if (objDp->getName() == "do_quality_bl") {
                        if (attrVal.toInt() != 0)
                            qd |= IEC60870_QUALITY_BLOCKED;
                    }
                    else if (objDp->getName() == "do_quality_ov") {
                        if (attrVal.toInt() != 0)
                            qd |= IEC60870_QUALITY_OVERFLOW;
                    }
                    else if (objDp->getName() == "do_quality_sb") {
                        if (attrVal.toInt() != 0)
                            qd |= IEC60870_QUALITY_SUBSTITUTED;
                    }
                    else if (objDp->getName() == "do_quality_nt") {
                        if (attrVal.toInt() != 0)
                            qd |= IEC60870_QUALITY_NON_TOPICAL;
                    }
                    else if (objDp->getName() == "do_ts") {
                        timestamp = (uint64_t)attrVal.toInt();
                        hasTimestamp = true;
                    }
                    else if (objDp->getName() == "dp_ts_iv") {
                        if (attrVal.toInt() != 0)
                            ts_iv = true;
                    }
                    else if (objDp->getName() == "dp_ts_su") {
                        if (attrVal.toInt() != 0)
                            ts_su = true;
                    }
                    else if (objDp->getName() == "dp_ts_sub") {
                        if (attrVal.toInt() != 0)
                            ts_sub = true;
                    }
                }

                if (cot == CS101_COT_ACTIVATION_CON)
                {
                    handleActCon(type, ca, ioa, isNegative);
                }
                else if (cot == CS101_COT_ACTIVATION_TERMINATION)
                {
                    handleActTerm(type, ca, ioa, isNegative);
                }
                else if (ca != -1 && ioa != -1 && cot != CS101_COT_UNKNOWN_COT && type != -1) {

                    IEC104DataPoint* dp = m_getDataPoint(ca, ioa, type);

                    if (dp) {

                        CP56Time2a ts = NULL;

                        struct sCP56Time2a _ts;

                        if (hasTimestamp) {
                            ts = CP56Time2a_createFromMsTimestamp(&_ts, timestamp);

                            if (ts) {
                                CP56Time2a_setInvalid(ts, ts_iv);
                                CP56Time2a_setSummerTime(ts, ts_su);
                                CP56Time2a_setSubstituted(ts, ts_sub);
                            }
                        }

                        // update internal value
                        m_updateDataPoint(dp, (IEC60870_5_TypeID)type, value, ts, qd);

                        if (cot == CS101_COT_PERIODIC || cot == CS101_COT_SPONTANEOUS ||
                            cot == CS101_COT_RETURN_INFO_REMOTE || cot == CS101_COT_RETURN_INFO_LOCAL ||
                            cot == CS101_COT_BACKGROUND_SCAN)
                        {
                            m_enqueueSpontDatapoint(dp, cot, (IEC60870_5_TypeID)type);
                        }
                    }
                    else {
                        Iec104Utility::log_error("%s data point %i:%i not found or type not expected", beforeLog.c_str(), ca, ioa); //LCOV_EXCL_LINE
                    }
                }

                if (value != nullptr) delete value;
            }
            else {
               Iec104Utility::log_info("%s Unknown data point name: %s -> ignored", beforeLog.c_str(), dp->getName().c_str());
               readingsSent++;
            }
        }

        n++;
    }

    return n;
}

/**
 * Print time in human readable format
 *
 * @param time CP56Time2a time format
 */
void IEC104Server::printCP56Time2a(CP56Time2a time)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::printCP56Time2a -";
    Iec104Utility::log_info(
        "%s %02i:%02i:%02i %02i/%02i/%04i", beforeLog.c_str(), CP56Time2a_getHour(time),
        CP56Time2a_getMinute(time), CP56Time2a_getSecond(time),
        CP56Time2a_getDayOfMonth(time), CP56Time2a_getMonth(time),
        CP56Time2a_getYear(time) + 2000);
}

//LCOV_EXCL_START
/**
 * Callback handler to log sent or received messages (optional)
 *
 * @param parameter
 * @param connection	connection object
 * @param msg	        message
 * @param msgSize	    message size
 * @param sent	        boolean
 */
void
IEC104Server::rawMessageHandler(void* parameter,
                                     IMasterConnection connection, uint8_t* msg,
                                     int msgSize, bool sent)

{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::rawMessageHandler -";
    if (sent)
        Iec104Utility::log_debug("%s SEND: ", beforeLog.c_str());
    else
        Iec104Utility::log_debug("%s RCVD: ", beforeLog.c_str());

    int i;
    for (i = 0; i < msgSize; i++)
    {
        Iec104Utility::log_debug("%s %02x ", beforeLog.c_str(), msg[i]);
    }
}
//LCOV_EXCL_STOP

/**
 * Callback handler for clock synchronization
 *
 * @param parameter
 * @param connection	connection object
 * @param asdu	        asdu
 * @param newTime	    new time
 * @return 		boolean
 */
bool
IEC104Server::clockSyncHandler(void* parameter,
                                    IMasterConnection connection,
                                    CS101_ASDU asdu, CP56Time2a newTime)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::clockSyncHandler -";
    IEC104Server* self = (IEC104Server*)parameter;

    Iec104Utility::log_info("%s Received time sync command with time:", beforeLog.c_str());//LCOV_EXCL_LINE

    printCP56Time2a(newTime);

    if (self->m_config->TimeSync()) {
        uint64_t newSystemTimeInMs = CP56Time2a_toMsTimestamp(newTime);

        /* TODO time as local time or UTC time? */
        nsSinceEpoch nsTime = newSystemTimeInMs * 10000000LLU;

        if (Hal_setTimeInNs(nsTime)) {
            Iec104Utility::log_info("%s Time sync success", beforeLog.c_str());//LCOV_EXCL_LINE
        }
        else {
            Iec104Utility::log_error("%s Time sync failed", beforeLog.c_str());//LCOV_EXCL_LINE
        }

        /* Set time for ACT_CON message */
        CP56Time2a_setFromMsTimestamp(newTime, Hal_getTimeInMs());
    }
    else {
        Iec104Utility::log_warn("%s Time sync disabled -> ignore time sync command", beforeLog.c_str());//LCOV_EXCL_LINE

        /* ignore time -> send negative response */
        CS101_ASDU_setNegative(asdu, true);
    }

    return true;
}

static bool
isBroadcastCA(int ca, CS101_AppLayerParameters alParams)
{
    if ((alParams->sizeOfCA == 1) && (ca == 0xff))
        return true;

    if ((alParams->sizeOfCA == 2) && (ca == 0xffff))
        return true;

    return false;
}

void
IEC104Server::sendInterrogationResponse(IMasterConnection connection, CS101_ASDU asdu, int ca, int qoi)
{
    CS101_ASDU_setCA(asdu, ca);

    IMasterConnection_sendACT_CON(connection, asdu, false);

    std::map<int, IEC104DataPoint*> ld = m_exchangeDefinitions[ca];

    std::map<int, IEC104DataPoint*>::iterator it;

    sCS101_StaticASDU _asdu;
    uint8_t ioBuf[250];

    CS101_AppLayerParameters alParams =
            IMasterConnection_getApplicationLayerParameters(connection);

    CS101_ASDU newASDU = CS101_ASDU_initializeStatic(&_asdu, alParams, false, CS101_COT_INTERROGATED_BY_STATION, CS101_ASDU_getOA(asdu), ca, false, false);

    for (it = ld.begin(); it != ld.end(); it++)
    {
        IEC104DataPoint* dp = it->second;

        if ((dp != nullptr) && dp->isMonitoringType()) {

            InformationObject io = NULL;

            //TODO when value not initialized use invalid/non-topical for quality
            //TODO when the value has no original timestamp then create timestamp when sending

            if(((dp->m_gi_groups >> (qoi - IEC60870_QOI_STATION)) & 1) != 1)
                continue;

            bool sendWithTimestamp = false;

            switch (dp->m_type) {
                case IEC60870_TYPE_SP:
                    if (sendWithTimestamp) {
                        sCP56Time2a cpTs;

                        CP56Time2a_createFromMsTimestamp(&cpTs, Hal_getTimeInMs());

                        io = (InformationObject)SinglePointWithCP56Time2a_create((SinglePointWithCP56Time2a)&ioBuf, dp->m_ioa, (bool)(dp->m_value.sp.value), dp->m_value.sp.quality, &cpTs);
                    }
                    else  {
                        io = (InformationObject)SinglePointInformation_create((SinglePointInformation)&ioBuf, dp->m_ioa, (bool)(dp->m_value.sp.value), dp->m_value.sp.quality);
                    }
                    break; //LCOV_EXCL_LINE

                case IEC60870_TYPE_DP:
                    if (sendWithTimestamp) {
                        sCP56Time2a cpTs;

                        CP56Time2a_createFromMsTimestamp(&cpTs, Hal_getTimeInMs());

                        io = (InformationObject)DoublePointWithCP56Time2a_create((DoublePointWithCP56Time2a)&ioBuf, dp->m_ioa, (DoublePointValue)dp->m_value.dp.value, dp->m_value.dp.quality, &cpTs);
                    }
                    else {
                        io = (InformationObject)DoublePointInformation_create((DoublePointInformation)&ioBuf, dp->m_ioa, (DoublePointValue)dp->m_value.dp.value, dp->m_value.dp.quality);
                    }
                    break; //LCOV_EXCL_LINE

                case IEC60870_TYPE_NORMALIZED:
                    if (sendWithTimestamp) {
                        sCP56Time2a cpTs;

                        CP56Time2a_createFromMsTimestamp(&cpTs, Hal_getTimeInMs());

                        io = (InformationObject)MeasuredValueNormalizedWithCP56Time2a_create((MeasuredValueNormalizedWithCP56Time2a)&ioBuf, dp->m_ioa, dp->m_value.mv_normalized.value, dp->m_value.mv_normalized.quality, &cpTs);

                    }
                    else {
                        io = (InformationObject)MeasuredValueNormalized_create((MeasuredValueNormalized)&ioBuf, dp->m_ioa, dp->m_value.mv_normalized.value, dp->m_value.mv_normalized.quality);
                    }
                    break; //LCOV_EXCL_LINE

                case IEC60870_TYPE_SCALED:
                    if (sendWithTimestamp) {
                        sCP56Time2a cpTs;

                        CP56Time2a_createFromMsTimestamp(&cpTs, Hal_getTimeInMs());

                        io = (InformationObject)MeasuredValueScaledWithCP56Time2a_create((MeasuredValueScaledWithCP56Time2a)&ioBuf, dp->m_ioa, dp->m_value.mv_scaled.value, dp->m_value.mv_scaled.quality, &cpTs);
                    }
                    else {
                        io = (InformationObject)MeasuredValueScaled_create((MeasuredValueScaled)&ioBuf, dp->m_ioa, dp->m_value.mv_scaled.value, dp->m_value.mv_scaled.quality);
                    }
                    break; //LCOV_EXCL_LINE

                case IEC60870_TYPE_SHORT:
                    if (sendWithTimestamp) {
                        sCP56Time2a cpTs;

                        CP56Time2a_createFromMsTimestamp(&cpTs, Hal_getTimeInMs());

                        io = (InformationObject)MeasuredValueShortWithCP56Time2a_create((MeasuredValueShortWithCP56Time2a)&ioBuf, dp->m_ioa, dp->m_value.mv_short.value, dp->m_value.mv_short.quality, &cpTs);
                    }
                    else {
                        io = (InformationObject)MeasuredValueShort_create((MeasuredValueShort)&ioBuf, dp->m_ioa, dp->m_value.mv_short.value, dp->m_value.mv_short.quality);
                    }
                    break; //LCOV_EXCL_LINE

                case IEC60870_TYPE_STEP_POS:
                    if (sendWithTimestamp) {
                        sCP56Time2a cpTs;

                        CP56Time2a_createFromMsTimestamp(&cpTs, Hal_getTimeInMs());

                        io = (InformationObject)StepPositionWithCP56Time2a_create((StepPositionWithCP56Time2a)&ioBuf, dp->m_ioa, dp->m_value.stepPos.posValue, dp->m_value.stepPos.transient, dp->m_value.stepPos.quality, &cpTs);
                    }
                    else {
                        io = (InformationObject)StepPositionInformation_create((StepPositionInformation)&ioBuf, dp->m_ioa, dp->m_value.stepPos.posValue, dp->m_value.stepPos.transient, dp->m_value.stepPos.quality);
                    }
                    break; //LCOV_EXCL_LINE

            }

            if (io) {
                if (CS101_ASDU_addInformationObject(newASDU, io) == false) {
                    IMasterConnection_sendASDU(connection, newASDU);

                    newASDU = CS101_ASDU_initializeStatic(&_asdu, alParams, false, CS101_COT_INTERROGATED_BY_STATION, CS101_ASDU_getOA(asdu), ca, false, false);

                    CS101_ASDU_addInformationObject(newASDU, io);
                }
            }
        }
    }

    if (newASDU) {
        if (CS101_ASDU_getNumberOfElements(newASDU) > 0) {
            IMasterConnection_sendASDU(connection, newASDU);
        }
    }


    IMasterConnection_sendACT_TERM(connection, asdu);
}

/**
 * Callback handler for station interrogation
 *
 * @param parameter
 * @param connection	connection object
 * @param asdu	        asdu
 * @param qoi	        qoi
 * @return 		boolean
 */
bool
IEC104Server::interrogationHandler(void* parameter,
                                        IMasterConnection connection,
                                        CS101_ASDU asdu, uint8_t qoi)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::interrogationHandler -";
    IEC104Server* self = (IEC104Server*)parameter;

    Iec104Utility::log_info("%s Received interrogation for group %i", beforeLog.c_str(), qoi);//LCOV_EXCL_LINE

    int ca = CS101_ASDU_getCA(asdu);

    CS101_AppLayerParameters alParams =
            IMasterConnection_getApplicationLayerParameters(connection);

    if (qoi < 20 || qoi >36) {
        IMasterConnection_sendACT_CON(connection, asdu, true);

        return true;
    }

    if (isBroadcastCA(ca, alParams)) {
        std::map<int, std::map<int, IEC104DataPoint*>>::iterator it;

        for (it = self->m_exchangeDefinitions.begin(); it != self->m_exchangeDefinitions.end(); it++)
        {
            ca = it->first;

            self->sendInterrogationResponse(connection, asdu, ca, qoi);
        }
    }
    else {
        if (self->m_exchangeDefinitions.count(ca) == 0) {
            CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_CA);
            IMasterConnection_sendACT_CON(connection, asdu, true);

            return true;
        }
        else {
            Iec104Utility::log_debug("%s Logical device with CA %i found", beforeLog.c_str(), ca);//LCOV_EXCL_LINE
            self->sendInterrogationResponse(connection, asdu, ca, qoi);
        }
    }

    return true;
}

/**
 * @brief Check if a command type is supported by the plugin
 *
 * @param typeId type ID of the received command
 * @return true the command is supported
 * @return false the command is unsupported
 */
static bool
isSupportedCommandType(IEC60870_5_TypeID typeId)
{
    if (typeId == C_SC_NA_1) return true;
    if (typeId == C_SC_TA_1) return true;
    if (typeId == C_DC_NA_1) return true;
    if (typeId == C_DC_TA_1) return true;
    if (typeId == C_RC_NA_1) return true;
    if (typeId == C_RC_TA_1) return true;
    if (typeId == C_SE_NA_1) return true;
    if (typeId == C_SE_NB_1) return true;
    if (typeId == C_SE_NC_1) return true;
    if (typeId == C_SE_TA_1) return true;
    if (typeId == C_SE_TB_1) return true;
    if (typeId == C_SE_TC_1) return true;

    return false;
}

/**
 * @brief Check if a received command with timestamp has a valid time
 *
 * @param typeId type of received command
 * @param io the information object of the received command
 * @return true the time is valid -> accept command
 * @return false  the time is invalid -> ingore command
 */
bool
IEC104Server::checkIfCmdTimeIsValid(int typeId, InformationObject io)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::checkIfCmdTimeIsValid -";
    if (m_config->CmdRecvTimeout() == 0)
        return true;

    CP56Time2a cmdTime = NULL;

    switch (typeId) {
        case C_SC_TA_1:
            cmdTime = SingleCommandWithCP56Time2a_getTimestamp((SingleCommandWithCP56Time2a)io);
            break; //LCOV_EXCL_LINE

        case C_DC_TA_1:
            cmdTime = DoubleCommandWithCP56Time2a_getTimestamp((DoubleCommandWithCP56Time2a)io);
            break; //LCOV_EXCL_LINE

        case C_RC_TA_1:
            cmdTime = StepCommandWithCP56Time2a_getTimestamp((StepCommandWithCP56Time2a)io);
            break; //LCOV_EXCL_LINE

        case C_SE_TA_1:
            cmdTime = SetpointCommandNormalizedWithCP56Time2a_getTimestamp((SetpointCommandNormalizedWithCP56Time2a)io);
            break; //LCOV_EXCL_LINE

        case C_SE_TB_1:
            cmdTime = SetpointCommandScaledWithCP56Time2a_getTimestamp((SetpointCommandScaledWithCP56Time2a)io);
            break; //LCOV_EXCL_LINE

        case C_SE_TC_1:
            cmdTime = SetpointCommandShortWithCP56Time2a_getTimestamp((SetpointCommandShortWithCP56Time2a)io);
            break; //LCOV_EXCL_LINE

        default:
            Iec104Utility::log_debug("%s Command with type %i is not supported", beforeLog.c_str(), typeId);
            return false;
    }

    if (cmdTime) {
        return checkTimestamp(cmdTime);
    }
    else {
        return false;
    }
}

/**
 * Callback handler for ASDU handling
 *
 * @param parameter
 * @param connection	connection object
 * @param asdu	        asdu
 * @return 		boolean
 */
bool
IEC104Server::asduHandler(void* parameter, IMasterConnection connection,
                               CS101_ASDU asdu)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::asduHandler -";
    IEC104Server* self = (IEC104Server*)parameter;

    if (isSupportedCommandType(CS101_ASDU_getTypeID(asdu)))
    {
        Iec104Utility::log_info("%s received command", beforeLog.c_str());//LCOV_EXCL_LINE

        bool sendResponse = true;

        if (CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION)
        {
            InformationObject io = CS101_ASDU_getElement(asdu, 0);

            if (io) {

                int ca = CS101_ASDU_getCA(asdu);

                std::map<int, IEC104DataPoint*> ld = self->m_exchangeDefinitions[ca];

                if (ld.empty() == false) {
                    /* check if command has an allowed OA */
                    if (self->m_config->IsOriginatorAllowed(CS101_ASDU_getOA(asdu)))
                    {
                        int ioa = InformationObject_getObjectAddress(io);

                        IEC104DataPoint* dp = ld[ioa];

                        if (dp)
                        {
                            auto typeId = CS101_ASDU_getTypeID(asdu);

                            if (dp->isMatchingCommand(typeId)) {

                                bool acceptCommand = true;

                                if (IEC104DataPoint::isCommandWithTimestamp(typeId)) {
                                    if (self->m_config->AllowCmdWithTime() == false) {
                                        acceptCommand = false;
                                    }
                                    else {
                                        if (self->checkIfCmdTimeIsValid(typeId, io) == false) {
                                            Iec104Utility::log_warn("%s command (%i) for %i:%i has invalid timestamp -> ignore",
                                                                    beforeLog.c_str(), typeId, ca, ioa);//LCOV_EXCL_LINE
                                            acceptCommand = false;

                                            /* send negative response -> according to IEC 60870-5-104 the command should be silently ignored instead! */
                                            CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
                                            CS101_ASDU_setNegative(asdu, true);

                                            IMasterConnection_sendASDU(connection, asdu);

                                            sendResponse = false;
                                        }
                                        else {
                                            Iec104Utility::log_debug("%s command time valid -> accept", beforeLog.c_str());//LCOV_EXCL_LINE
                                        }
                                    }
                                }
                                else {
                                    if (self->m_config->AllowCmdWithoutTime() == false) {
                                        acceptCommand = false;
                                    }
                                }

                                if (acceptCommand) {
                                    CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);

                                    if (self->forwardCommand(asdu, io, connection) == false) {
                                        CS101_ASDU_setNegative(asdu, true);
                                    }
                                    else {
                                        /* send ACT-CON later when south side feedback is received */
                                        sendResponse = false;
                                    }
                                }
                                else {
                                    Iec104Utility::log_warn("%s Command not accepted", beforeLog.c_str()); //LCOV_EXCL_LINE
                                    CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_TYPE_ID);
                                }
                            }
                            else {
                                Iec104Utility::log_warn("%s Unknown command type", beforeLog.c_str()); //LCOV_EXCL_LINE
                                CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_TYPE_ID);
                            }
                        }
                        else {
                            Iec104Utility::log_warn("%s Unknown IOA (%i:%i)", beforeLog.c_str(), ca, ioa); //LCOV_EXCL_LINE
                            CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
                        }
                    }
                    else {
                        Iec104Utility::log_warn("%s Originator address %i not allowed", beforeLog.c_str(), CS101_ASDU_getOA(asdu)); //LCOV_EXCL_LINE
                    }
                }
                else {
                    Iec104Utility::log_warn("%s Unknown CA: %i", beforeLog.c_str(), ca); //LCOV_EXCL_LINE
                    CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_CA);
                }

                InformationObject_destroy(io);
            }
            else {
                Iec104Utility::log_warn("%s Unknown type or information object missing", beforeLog.c_str()); //LCOV_EXCL_LINE
                CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_TYPE_ID);
            }
        }
        else {
            CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT);
        }

        if (sendResponse)
        {
            IMasterConnection_sendASDU(connection, asdu);
        }

        return true;
    }

    return false;
}

/**
 * Callback handler for connection request handling
 *
 * @param parameter
 * @param ipAddress	    incoming connection request IP address
 * @return 		boolean
 */
bool
IEC104Server::connectionRequestHandler(void* parameter,
                                            const char* ipAddress)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::connectionRequestHandler -";
    Iec104Utility::log_info("%s New connection request from %s", beforeLog.c_str(), ipAddress); //LCOV_EXCL_LINE

    return true;
}

/**
 * Callback handler for connection event handling
 *
 * @param parameter
 * @param connection	connection object
 * @param event         peer connection event object
 */
void
IEC104Server::connectionEventHandler(void* parameter,
                                          IMasterConnection con,
                                          CS104_PeerConnectionEvent event)
{
    std::string beforeLog = Iec104Utility::PluginName + " - IEC104Server::connectionRequestHandler -";
    IEC104Server* self = (IEC104Server*)parameter;

    char ipAddrBuf[100];
    ipAddrBuf[0] = 0;

    IMasterConnection_getPeerAddress(con, ipAddrBuf, 100);

    if (event == CS104_CON_EVENT_CONNECTION_OPENED)
    {
        Iec104Utility::log_info("%s Connection opened (%s)", beforeLog.c_str(), ipAddrBuf); //LCOV_EXCL_LINE
    }
    else if (event == CS104_CON_EVENT_CONNECTION_CLOSED)
    {
        Iec104Utility::log_info("%s Connection closed (%s)", beforeLog.c_str(), ipAddrBuf);//LCOV_EXCL_LINE
        self->removeOutstandingCommands(con);
    }
    else if (event == CS104_CON_EVENT_ACTIVATED)
    {
        Iec104Utility::log_info("%s Connection activated (%s)", beforeLog.c_str(), ipAddrBuf);//LCOV_EXCL_LINE
    }
    else if (event == CS104_CON_EVENT_DEACTIVATED)
    {
        Iec104Utility::log_info("%s Connection deactivated (%s)", beforeLog.c_str(), ipAddrBuf);//LCOV_EXCL_LINE
        self->removeOutstandingCommands(con);
    }
}

/**
 * Stop the IEC104 Server
 */
void
IEC104Server::stop()
{
    if (m_started == true)
    {
        m_started = false;

        if (m_monitoringThread != nullptr) {
            m_monitoringThread->join();
            delete m_monitoringThread;
            m_monitoringThread = nullptr;
        }
    }

    if (m_slave)
    {
        CS104_Slave_destroy(m_slave);
        m_slave = nullptr;
    }

    if (m_tlsConfig)
    {
        TLSConfiguration_destroy(m_tlsConfig);
        m_tlsConfig = nullptr;
    }
}
