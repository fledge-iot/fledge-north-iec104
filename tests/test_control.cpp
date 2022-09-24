#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iec104.h>

#include <memory>
#include <utility>
#include <plugin_api.h>

#include "cs104_connection.h"
using namespace std;

static string protocol_stack = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
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
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
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
class ControlTest : public testing::Test
{
protected:
    IEC104Server* iec104Server;  // Object on which we call for tests
    CS104_Connection connection;

    // Setup is ran for every tests, so each variable are reinitialised
    void SetUp() override
    {
        operateHandlerCalled = 0;

        // Init iec104server object
        iec104Server = new IEC104Server();
        const char* ip = "127.0.0.1";
        uint16_t port = IEC_60870_5_104_DEFAULT_PORT;
        // Create connection
        connection = CS104_Connection_create(ip, port);
    }

    static int operateHandlerCalled;

    static int operateHandler(char *operation, int paramCount, char *parameters[], ControlDestination destination, ...);

    // TearDown is ran for every tests, so each variable are destroyed again
    void TearDown() override
    {
        CS104_Connection_destroy(connection);
        iec104Server->stop();

        delete iec104Server;
    }
};

int ControlTest::operateHandlerCalled;

int ControlTest::operateHandler(char *operation, int paramCount, char *parameters[], ControlDestination destination, ...)
{
    printf("operateHandler called\n");
    operateHandlerCalled++;

    return 1;
}

template <class T>
static Datapoint* createDatapoint(const std::string& dataname,
                                    const T value)
{
    DatapointValue dp_value = DatapointValue(value);
    return new Datapoint(dataname, dp_value);
}

template <class T>
static Datapoint* createDataObject(const char* type, int ca, int ioa, int cot,
    const T value, bool iv, bool bl, bool ov, bool sb, bool nt)
{
    auto* datapoints = new vector<Datapoint*>;

    datapoints->push_back(createDatapoint("do_type", type));
    datapoints->push_back(createDatapoint("do_ca", (int64_t)ca));
    datapoints->push_back(createDatapoint("do_oa", (int64_t)0));
    datapoints->push_back(createDatapoint("do_cot", (int64_t)cot));
    datapoints->push_back(createDatapoint("do_test", (int64_t)0));
    datapoints->push_back(createDatapoint("do_negative", (int64_t)0));
    datapoints->push_back(createDatapoint("do_ioa", (int64_t)ioa));
    datapoints->push_back(createDatapoint("do_value", value));
    datapoints->push_back(createDatapoint("do_quality_iv", (int64_t)iv));
    datapoints->push_back(createDatapoint("do_quality_bl", (int64_t)bl));
    datapoints->push_back(createDatapoint("do_quality_ov", (int64_t)ov));
    datapoints->push_back(createDatapoint("do_quality_sb", (int64_t)sb));
    datapoints->push_back(createDatapoint("do_quality_nt", (int64_t)nt));

    DatapointValue dpv(datapoints, true);

    Datapoint* dp = new Datapoint("data_object", dpv);

    return dp;
}

TEST_F(ControlTest, CreateReading)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    auto* dataobjects = new vector<Datapoint*>;

    dataobjects->push_back(createDataObject("M_SP_NA_1", 45, 945, CS101_COT_SPONTANEOUS, (int64_t)1, false, false, false, false, false));
    //dataobjects->push_back(createDataObject("M_SP_NA_1", 45, 946, CS101_COT_SPONTANEOUS, (int64_t)0, false, false, false, false, false));
    //dataobjects->push_back(createDataObject("M_SP_NA_1", 45, 947, CS101_COT_SPONTANEOUS, (int64_t)0, false, false, false, false, false));

    Reading* reading = new Reading(std::string("TS1"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    delete reading;
    delete dataobjects;
}

TEST_F(ControlTest, ReceiveSinglePointCommand)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandler);

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject sc = (InformationObject)SingleCommand_create(NULL, 10005, true, false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);
}

TEST_F(ControlTest, SinglePointCommandUnknownCA)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandler);

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject sc = (InformationObject)SingleCommand_create(NULL, 10005, true, false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 21, sc);

    InformationObject_destroy(sc);

    Thread_sleep(500);

    ASSERT_EQ(0, operateHandlerCalled);
}

TEST_F(ControlTest, ReceiveUnexpectedDoublePointCommand)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandler);

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject sc = (InformationObject)DoubleCommand_create(NULL, 10005, 1, false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(500);

    ASSERT_EQ(0, operateHandlerCalled);
}
