#ifndef _IEC104SERVER_H
#define _IEC104SERVER_H

/*
 * Fledge IEC 104 north plugin.
 *
 * Copyright (c) 2020, RTE (https://www.rte-france.com)
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Akli Rahmoun <akli.rahmoun at rte-france.com>
 */

// clang-format off
#include <reading.h>
#include <config_category.h>
#include <logger.h>
#include <string>
#include <vector>
#include <map>
#include "lib60870/cs104_slave.h"
#include "lib60870/cs101_information_objects.h"
#include "lib60870/hal_thread.h"
#include "lib60870/hal_time.h"
// clang-format on

class IEC104DataPoint
{
public:

    IEC104DataPoint(std::string label, int ca, int ioa, int type);
    ~IEC104DataPoint();

    int m_ca;
    int m_ioa;
    int m_type;
    std::string m_label;

    union {
        struct {
            unsigned int value : 1;
            uint8_t quality;
        } sp; /* IEC60870_TYPE_SP */

        struct {
            unsigned int value : 2;
            uint8_t quality;
        } dp; /* IEC60870_TYPE_DP */

        struct {
            int posValue : 7; /* I7[1..7]<-64..+63> */
            unsigned int transient : 1;
            uint8_t quality;
        } stepPos; /* IEC60870_TYPE_STEP_POS */

        struct {
            float value;
            uint8_t quality;
        } mv_normalized; /* IEC60870_TYPE_NORMALIZED */

        struct {
            int16_t value;
            uint8_t quality;
        } mv_scaled; /* IEC60870_TYPE_SCALED */

        struct {
            float value;
            uint8_t quality;
        } mv_short; /* IEC60870_TYPE_SHORT */

        uint32_t bitstring; /* IEC60870_TYPE_BITSTRING */

        struct {
            int32_t value;
            struct {
                unsigned int seq : 5;
                unsigned int cy : 1;
                unsigned int ca : 1;
                unsigned int invalid : 1;
            } quality;
        } counter; /* IEC60870_TYPE_COUNTER */

        struct {
            uint8_t sep;
            uint16_t elapsed;
        } single_event; /* IEC60870_TYPE_SINGLE_EVENT */

        struct {
            uint8_t spe;
            uint8_t quality;
            uint16_t elapsed;
        } start_events; /* IEC60870_TYPE_PACKED_START_EVENTS */

        struct {
            uint8_t oci;
            uint8_t quality;
            uint16_t elapsed;
        } out_info; /* IEC60870_TYPE_PACKED_OUTPUT_INFO */

        struct {
            union {
                float f;
                int16_t i;
            } val;
            unsigned int kind : 6;
            unsigned int active : 1;
            unsigned int refIoa : 24;
        } param_mv; /* IEC60870_TYPE_PARAM_MV_... */

    } m_value;
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

private:

    std::map<int, std::map<int, IEC104DataPoint*>> m_exchangeDefinitions;
    
    IEC104DataPoint* m_getDataPoint(int ca, int ioa, int typeId);
    void m_enqueueSpontDatapoint(IEC104DataPoint* dp, CS101_CauseOfTransmission cot, IEC60870_5_TypeID typeId);
    void m_updateDataPoint(IEC104DataPoint* dp, IEC60870_5_TypeID typeId, DatapointValue* value, CP56Time2a ts, uint8_t quality);

    static void printCP56Time2a(CP56Time2a time);
    static void rawMessageHandler(void* parameter, IMasterConnection connection,
                                  uint8_t* msg, int msgSize, bool sent);
    static bool clockSyncHandler(void* parameter, IMasterConnection connection,
                                 CS101_ASDU asdu, CP56Time2a newTime);
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
};

#endif