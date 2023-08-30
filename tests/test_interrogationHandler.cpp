#include <gtest/gtest.h>
#include <iec104.h>

#include <memory>
#include <utility>

#include <lib60870/linked_list.h>

#include "cs104_connection.h"
#include <plugin_api.h>

using namespace std;

static string protocol_stack = QUOTE({
        "protocol_stack" : {
            "name" : "iec104client",
            "version" : "1.0",
            "transport_layer" : {
                "connection" : {
                    "path" : [
                        {"srv_ip" : "127.0.0.1", "clt_ip" : "", "port" : 2404},
                        {"srv_ip" : "127.0.0.1", "clt_ip" : "", "port" : 2404}
                    ],
                    "tls" : false
                },
                "llevel" : 1,
                "k_value" : 12,
                "w_value" : 8,
                "t0_timeout" : 10,
                "t1_timeout" : 15,
                "t2_timeout" : 10,
                "t3_timeout" : 20,
                "conn_all" : true,
                "start_all" : false,
                "conn_passv" : false
            },
            "application_layer" : {
                "orig_addr" : 0,
                "ca_asdu_size" : 2,
                "ioaddr_size" : 3,
                "startup_time" : 180,
                "asdu_size" : 0,
                "gi_time" : 60,
                "gi_cycle" : false,
                "gi_all_ca" : false,
                "gi_repeat_count" : 2,
                "disc_qual" : "NT",
                "send_iv_time" : 0,
                "tsiv" : "REMOVE",
                "utc_time" : false,
                "comm_wttag" : false,
                "comm_parallel" : 0,
                "exec_cycl_test" : false,
                "startup_state" : true,
                "reverse" : false,
                "time_sync" : false
            }
        }
    });

static string tls = QUOTE({
        "tls_conf:" : {
            "private_key" : "server-key.pem",
            "server_cert" : "server.cer",
            "ca_cert" : "root.cer"
        }
    });
    string exchanged_data = QUOTE({
        "exchanged_data" : {
            "name" : "iec104client",
            "version" : "1.0",
            "datapoints":[
                {
                    "label":"TS1",
                    "pivot_id":"ID114562",
                    "pivot_type":"SpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-672",
                          "typeid":"M_SP_NA_1"
                       },
                       {
                          "name":"tase2",
                          "address":"S_114562",
                          "typeid":"Data_StateQTimeTagExtended"
                       }
                    ]
                },
                {
                    "label":"TS2",
                    "pivot_id":"ID114563",
                    "pivot_type":"SpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-674",
                          "typeid":"M_SP_NA_1"
                       }
                    ]
                },
                {
                    "label":"TM1",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-984",
                          "typeid":"M_ME_NA_1"
                       },
                       {
                          "name":"tase2",
                          "address":"S_114562",
                          "typeid":"Data_RealQ"
                       }
                    ]
                },
                {
                    "label":"TM2",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-994",
                          "typeid":"M_ME_NB_1"
                       }
                    ]
                },
                {
                    "label":"TM3",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-996",
                          "typeid":"M_ME_NC_1"
                       }
                    ]
                },
                {
                    "label":"TM4",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-997",
                          "typeid":"M_ME_NC_1"
                       }
                    ]
                },
                {
                    "label":"TM13",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"145-996",
                          "typeid":"M_ME_NC_1"
                       }
                    ]
                },
                {
                    "label":"TM14",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"145-997",
                          "typeid":"M_ME_NC_1"
                       }
                    ]
                },
                {
                    "label":"TM15",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"145-2997",
                          "typeid":"M_DP_NA_1"
                       }
                    ]
                },
                {
                    "label":"TM16",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"145-3997",
                          "typeid":"M_DP_TB_1"
                       }
                    ]
                },
                {
                    "label":"TM17",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"145-4997",
                          "typeid":"M_ME_TD_1"
                       }
                    ]
                },
                {
                    "label":"TM18",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"145-5997",
                          "typeid":"M_ME_TE_1"
                       }
                    ]
                },
                {
                    "label":"TM19",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"145-6997",
                          "typeid":"M_ME_TF_1"
                       }
                    ]
                },
                {
                    "label":"TM20",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"145-7997",
                          "typeid":"M_ST_NA_1"
                       }
                    ]
                },
                {
                    "label":"TM21",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"145-8997",
                          "typeid":"M_ST_TB_1"
                       }
                    ]
                }
            ]
        }
    });


    string exchanged_data_2 = QUOTE({
        "exchanged_data" : {
            "name" : "iec104client",
            "version" : "1.0",
            "datapoints":[
                {
                    "label":"TS1",
                    "pivot_id":"ID114562",
                    "pivot_type":"SpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-672",
                          "typeid":"M_SP_NA_1",
                          "gi_groups": "station,11,12"
                       },
                       {
                          "name":"tase2",
                          "address":"S_114562",
                          "typeid":"Data_StateQTimeTagExtended",
                          "gi_groups": "station,11,12"
                       }
                    ]
                },
                {
                    "label":"TS2",
                    "pivot_id":"ID114563",
                    "pivot_type":"SpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-674",
                          "typeid":"M_SP_NA_1",
                          "gi_groups": 4
                       }
                    ]
                },
                {
                    "label":"TM1",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-984",
                          "typeid":"M_ME_NA_1",
                          "gi_groups": "11"
                       },
                       {
                          "name":"tase2",
                          "address":"S_114562",
                          "typeid":"Data_RealQ",
                          "gi_groups": "11"
                       }
                    ]
                },
                {
                    "label":"TM2",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-994",
                          "typeid":"M_ME_NB_1",
                          "gi_groups": "1"
                       }
                    ]
                },
                {
                    "label":"TM3",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-996",
                          "typeid":"M_ME_NC_1",
                          "gi_groups": "15,INVALID"
                       }
                    ]
                },
                {
                    "label":"TM4",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-997",
                          "typeid":"M_ME_NC_1",
                          "gi_groups": "11,station,12"
                       }
                    ]
                },
                {
                    "label":"TM13",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-998",
                          "typeid":"M_ME_NC_1",
                          "gi_groups": "11"
                       }
                    ]
                },
                {
                    "label":"TM14",
                    "pivot_id":"ID99876",
                    "pivot_type":"DpsTyp",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-999",
                          "typeid":"M_ME_NC_1",
                          "gi_groups": "11"
                       }
                    ]
                }
            ]
        }
    });

// Class to be called in each test, contains fixture to be used in
class InterrogationHandlerTest : public testing::Test
{
public:
    LinkedList receivedASDUs;

protected:
    IEC104Server* iec104Server;  // Object on which we call for tests
    CS104_Connection connection;

    // Setup is ran for every tests, so each variable are reinitialised
    void SetUp() override
    {
        // Init iec104server object
        iec104Server = new IEC104Server();
        const char* ip = "127.0.0.1";
        uint16_t port = IEC_60870_5_104_DEFAULT_PORT;
        // Create connection
        connection = CS104_Connection_create(ip, port);
    }

    // TearDown is ran for every tests, so each variable are destroyed again
    void TearDown() override
    {
        CS104_Connection_destroy(connection);
        iec104Server->stop();

        delete iec104Server;
    }
};

struct sASDU_testInfo
{
    IEC60870_5_TypeID typeId;
    int ca;
    int ioa;
    int numberOfIOs;
    CS101_CauseOfTransmission cot;
    int oa;
    int intValue;
    float floatValue;
};

static bool test1_ASDUReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
    printf("ASDU received - type: %i CA: %i COT: %i\n", CS101_ASDU_getTypeID(asdu), CS101_ASDU_getCA(asdu), CS101_ASDU_getCOT(asdu));

    InterrogationHandlerTest* self = (InterrogationHandlerTest*)parameter;
    
    if (self->receivedASDUs) {
        struct sASDU_testInfo* newAsduInfo = (struct sASDU_testInfo*)calloc(1, sizeof(struct sASDU_testInfo));

        newAsduInfo->typeId = CS101_ASDU_getTypeID(asdu);
        newAsduInfo->ca = CS101_ASDU_getCA(asdu);
        newAsduInfo->cot = CS101_ASDU_getCOT(asdu);
        newAsduInfo->numberOfIOs = CS101_ASDU_getNumberOfElements(asdu);
        newAsduInfo->oa = CS101_ASDU_getOA(asdu);
        
        InformationObject io = CS101_ASDU_getElement(asdu, 0);

        if (io) {
            newAsduInfo->ioa = InformationObject_getObjectAddress(io);

            InformationObject_destroy(io);
        }
        else {
            newAsduInfo->ioa = -1;
        }

        LinkedList_add(self->receivedASDUs, newAsduInfo);
    }

    return true;
}

// Test the callback handler for station interrogation
TEST_F(InterrogationHandlerTest, InterrogationHandlerSingleCA)
{
    receivedASDUs = LinkedList_create();

    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);
    
    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        CS104_Connection_sendInterrogationCommand(
            connection, CS101_COT_ACTIVATION, 45, IEC60870_QOI_STATION);

        Thread_sleep(500);

        ASSERT_EQ(6, LinkedList_size(receivedASDUs));

        struct sASDU_testInfo* asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 0));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_ACTIVATION_CON, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(C_IC_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 1));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(2, asdu->numberOfIOs);
        ASSERT_EQ(M_SP_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 2));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 3));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NB_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 4));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(2, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NC_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 5));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_ACTIVATION_TERMINATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(C_IC_NA_1, asdu->typeId);
    }
    else {
        ASSERT_TRUE(false);
    }

    LinkedList_destroy(receivedASDUs);
}

// Test the callback handler for station interrogation
TEST_F(InterrogationHandlerTest, InterrogationHandlerBroadcastCA)
{
    receivedASDUs = LinkedList_create();

    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);
    
    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        CS104_Connection_sendInterrogationCommand(
            connection, CS101_COT_ACTIVATION, 0xffff, IEC60870_QOI_STATION);

        Thread_sleep(500);

        ASSERT_EQ(14, LinkedList_size(receivedASDUs));

        struct sASDU_testInfo* asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 0));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_ACTIVATION_CON, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(C_IC_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 1));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(2, asdu->numberOfIOs);
        ASSERT_EQ(M_SP_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 2));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 3));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NB_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 4));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(2, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NC_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 5));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_ACTIVATION_TERMINATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(C_IC_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 6));

        ASSERT_EQ(145, asdu->ca);
        ASSERT_EQ(CS101_COT_ACTIVATION_CON, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(C_IC_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 7));

        ASSERT_EQ(145, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(2, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NC_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 8));

        ASSERT_EQ(145, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(2, asdu->numberOfIOs);
        ASSERT_EQ(M_DP_NA_1, asdu->typeId);

        /* NOTE: M_DP_TB_1 data is put into the same ASDU as M_DP_NA_1 
           in general during interrogation requests all data types are sent without timestamp! */

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs,9));

        ASSERT_EQ(145, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        //ASSERT_EQ(2, asdu->numberOfIOs);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NA_1, asdu->typeId);

         asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 10));

        ASSERT_EQ(145, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NB_1, asdu->typeId);

         asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 11));

        ASSERT_EQ(145, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NC_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 12));

        ASSERT_EQ(145, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(2, asdu->numberOfIOs);
        ASSERT_EQ(M_ST_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 13));

        ASSERT_EQ(145, asdu->ca);
        ASSERT_EQ(CS101_COT_ACTIVATION_TERMINATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(C_IC_NA_1, asdu->typeId);
    }
    else {
        ASSERT_TRUE(false);
    }

    LinkedList_destroy(receivedASDUs);
}

TEST_F(InterrogationHandlerTest, InterrogationForUnknownCA)
{
    receivedASDUs = LinkedList_create();

    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);
    
    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        CS104_Connection_sendInterrogationCommand(
            connection, CS101_COT_ACTIVATION, 21, IEC60870_QOI_STATION);

        Thread_sleep(500);

        ASSERT_EQ(1, LinkedList_size(receivedASDUs));

        struct sASDU_testInfo* asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 0));

        ASSERT_EQ(21, asdu->ca);
        ASSERT_EQ(CS101_COT_ACTIVATION_CON, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(C_IC_NA_1, asdu->typeId);
    }
    else {
        ASSERT_TRUE(false);
    }

    LinkedList_destroy(receivedASDUs);
}

// Test the callback handler for station interrogation
TEST_F(InterrogationHandlerTest, InterrogationHandlerSingleCAGIGroups)
{
    receivedASDUs = LinkedList_create();

    iec104Server->setJsonConfig(protocol_stack, exchanged_data_2, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);
    
    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        CS104_Connection_sendInterrogationCommand(
            connection, CS101_COT_ACTIVATION, 45, IEC60870_QOI_GROUP_11);

        Thread_sleep(500);

        ASSERT_EQ(5, LinkedList_size(receivedASDUs));

        struct sASDU_testInfo* asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 0));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_ACTIVATION_CON, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(C_IC_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 1));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(M_SP_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 2));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NA_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 3));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_INTERROGATED_BY_STATION, asdu->cot);
        ASSERT_EQ(3, asdu->numberOfIOs);
        ASSERT_EQ(M_ME_NC_1, asdu->typeId);

        asdu = (struct sASDU_testInfo*)LinkedList_getData(LinkedList_get(receivedASDUs, 4));

        ASSERT_EQ(45, asdu->ca);
        ASSERT_EQ(CS101_COT_ACTIVATION_TERMINATION, asdu->cot);
        ASSERT_EQ(1, asdu->numberOfIOs);
        ASSERT_EQ(C_IC_NA_1, asdu->typeId);


    }
    else {
        ASSERT_TRUE(false);
    }

    LinkedList_destroy(receivedASDUs);
}