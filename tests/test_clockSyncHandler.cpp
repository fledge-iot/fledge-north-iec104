#include <gtest/gtest.h>

#include "linked_list.h"
#include <lib60870/hal_thread.h>
#include <lib60870/hal_time.h>

#include "iec104.h"
#include "cs104_connection.h"

using namespace std;

static string protocol_stack_1 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "srv_ip":"0.0.0.0",
                "port":2404,
                "tls":false,
                "k_value":12,
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":20000,
                "cmd_recv_timeout":5000,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ]
            }
        }
    });

static string protocol_stack_2 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "srv_ip":"0.0.0.0",
                "port":2404,
                "tls":false,
                "k_value":12,
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":true,
                "cmd_exec_timeout":20000,
                "cmd_recv_timeout":5000,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ]
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

static string exchanged_data = QUOTE({
        "exchanged_data" : {
            "name" : "iec104server",
            "version" : "1.0",
            "datapoints":[
                {
                    "label":"TS1",
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
                    "label":"TM1",
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
                    "label":"CM1",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-10005",
                          "typeid":"C_SC_NA_1",
                          "termination_timeout": 3000
                       }
                    ]
                }
            ]
        }
    });

// Class to be called in each test, contains fixture to be used in
class ClockSyncHandlerTest : public testing::Test
{
public:
    LinkedList receivedAsdus;

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

        receivedAsdus = LinkedList_create();
    }

    // TearDown is ran for every tests, so each variable are destroyed again
    void TearDown() override
    {
        CS104_Connection_destroy(connection);
        iec104Server->stop();

        LinkedList_destroyDeep(receivedAsdus, (LinkedListValueDeleteFunction)CS101_ASDU_destroy);

        delete iec104Server;
    }
};

static bool asduHandler(void* parameter, int address, CS101_ASDU asdu)
{
    ClockSyncHandlerTest* self = (ClockSyncHandlerTest*)parameter;

    LinkedList_add(self->receivedAsdus, CS101_ASDU_clone(asdu, NULL));

    return true;
}

TEST_F(ClockSyncHandlerTest, clockSyncFalse)
{
    iec104Server->setJsonConfig(protocol_stack_1, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, asduHandler, this);

    bool result = CS104_Connection_connect(connection);

    ASSERT_TRUE(result);

    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        /* Send clock synchronization command */
        struct sCP56Time2a newTime;

        CP56Time2a_createFromMsTimestamp(&newTime, Hal_getTimeInMs());
        CS104_Connection_sendClockSyncCommand(connection, 1, &newTime);

        Thread_sleep(500);

        ASSERT_EQ(1, LinkedList_size(receivedAsdus));
        
        CS101_ASDU firstAsdu = (CS101_ASDU)LinkedList_getData(LinkedList_get(receivedAsdus, 0));

        ASSERT_EQ(CS101_COT_ACTIVATION_CON, CS101_ASDU_getCOT(firstAsdu));
        ASSERT_TRUE(CS101_ASDU_isNegative(firstAsdu));
    }
}

TEST_F(ClockSyncHandlerTest, clockSyncTrue)
{
    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, asduHandler, this);

    bool result = CS104_Connection_connect(connection);

    ASSERT_TRUE(result);

    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        /* Send clock synchronization command */
        struct sCP56Time2a newTime;

        CP56Time2a_createFromMsTimestamp(&newTime, Hal_getTimeInMs());
        CS104_Connection_sendClockSyncCommand(connection, 1, &newTime);

        Thread_sleep(500);

        ASSERT_EQ(1, LinkedList_size(receivedAsdus));
        
        CS101_ASDU firstAsdu = (CS101_ASDU)LinkedList_getData(LinkedList_get(receivedAsdus, 0));

        ASSERT_EQ(C_CS_NA_1, CS101_ASDU_getTypeID(firstAsdu));
        ASSERT_EQ(CS101_COT_ACTIVATION_CON, CS101_ASDU_getCOT(firstAsdu));
        ASSERT_FALSE(CS101_ASDU_isNegative(firstAsdu));
    }
}