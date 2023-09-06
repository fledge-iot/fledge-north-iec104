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
                "t3_timeout":20,
                "mode": "accept_if_south_connx_started"
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":1,
                "cmd_recv_timeout":1,
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
            },
            "south_monitoring": [
                {"asset": "CONSTAT-1"},
                {"asset": "CONSTAT-2"}
            ]
        }
    });
    
static string tls = QUOTE({
        "tls_conf" : {
            "private_key" : "iec104_server.key",
            "own_cert" : "iec104_server.cer",
            "ca_certs" : [
                {
                    "cert_file": "iec104_ca.cer"
                }
            ]
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

static string exchanged_data_2 = QUOTE({
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
                },
                {
                    "label":"CM2",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-10010",
                          "typeid":"C_SE_TC_1",
                          "termination_timeout": 1
                       }
                    ]
                }
            ]
        }
    });

// Class to be called in each test, contains fixture to be used in
class LegacyModeTest : public testing::Test
{
protected:
    IEC104Server* iec104Server;  // Object on which we call for tests
    CS104_Connection connection;

    // Setup is ran for every tests, so each variable are reinitialised
    void SetUp() override
    {
        operateHandlerCalled = 0;
        asduHandlerCalled = 0;
        actConReceived = 0;
        actConNegative = false;
        actTermReceived = 0;

        // Init iec104server object
        iec104Server = new IEC104Server();
        const char* ip = "127.0.0.1";
        uint16_t port = IEC_60870_5_104_DEFAULT_PORT;
        // Create connection
        connection = CS104_Connection_create(ip, port);

        CS104_Connection_setASDUReceivedHandler(connection, m_asduReceivedHandler, this);
    }

    static int operateHandlerCalled;
    static std::string calledOperation;

    static int operateHandler(char *operation, int paramCount, char* names[], char *parameters[], ControlDestination destination, ...);

    // TearDown is ran for every tests, so each variable are destroyed again
    void TearDown() override
    {
        CS104_Connection_destroy(connection);
        iec104Server->stop();

        delete iec104Server;
    }

    void ForwardCommandAck(const char* cmdName, const char* type, int ca, int ioa, int cot, bool negative);

    int asduHandlerCalled = 0;
    int actConReceived = 0;
    bool actConNegative = false;
    int actTermReceived = 0;

    void SendSouthEvent(std::string asset, bool withConnx, std::string connxValue, bool withGiStatus, std::string giStatusValue);

    static bool m_asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu);
};

bool
LegacyModeTest::m_asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
    LegacyModeTest* self = (LegacyModeTest*)parameter;

    self->asduHandlerCalled++;

    printf("CS101_ASDU: type: %i ca: %i cot: %i\n", CS101_ASDU_getTypeID(asdu), CS101_ASDU_getCA(asdu), CS101_ASDU_getCOT(asdu));
    
    self->actConNegative = false;

    if (CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION_CON) {
        self->actConReceived++;
        self->actConNegative = CS101_ASDU_isNegative(asdu);
    }

    if (CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION_TERMINATION) {
        self->actTermReceived++;
    }

    return true;
}

int LegacyModeTest::operateHandlerCalled;
std::string LegacyModeTest::calledOperation = "";

int LegacyModeTest::operateHandler(char *operation, int paramCount, char* names[], char *parameters[], ControlDestination destination, ...)
{
    printf("operateHandler called\n");
    operateHandlerCalled++;

    calledOperation.assign(operation);

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

static Datapoint*
createCommandAck(const char* type, int ca, int ioa, int cot, bool negative)
{
    auto* datapoints = new vector<Datapoint*>;

    datapoints->push_back(createDatapoint("do_type", type));
    datapoints->push_back(createDatapoint("do_ca", (int64_t)ca));
    datapoints->push_back(createDatapoint("do_oa", (int64_t)0));
    datapoints->push_back(createDatapoint("do_cot", (int64_t)cot));
    datapoints->push_back(createDatapoint("do_test", (int64_t)0));
    datapoints->push_back(createDatapoint("do_negative", (int64_t)negative));
    datapoints->push_back(createDatapoint("do_ioa", (int64_t)ioa));

    DatapointValue dpv(datapoints, true);

    Datapoint* dp = new Datapoint("data_object", dpv);

    return dp;
}

static Datapoint*
createSouthEvent(bool withConnx, std::string connxValue, bool withGiStatus, std::string giStatusValue)
{
    auto* datapoints = new vector<Datapoint*>;

    if (withConnx) {
        datapoints->push_back(createDatapoint("connx_status", connxValue));
    }

    if (withGiStatus) {
        datapoints->push_back(createDatapoint("gi_status", giStatusValue));
    }

    DatapointValue dpv(datapoints, true);

    Datapoint* dp = new Datapoint("south_event", dpv);

    return dp;
}

void
LegacyModeTest::SendSouthEvent(std::string asset, bool withConnx, std::string connxValue, bool withGiStatus, std::string giStatusValue)
{
    Datapoint* southEvent = createSouthEvent(true, connxValue, withGiStatus, giStatusValue);

    auto* southEvents = new vector<Datapoint*>;

    southEvents->push_back(southEvent);

    //TODO send south event connx_started
    Reading* reading = new Reading(asset, *southEvents);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);
}

void 
LegacyModeTest::ForwardCommandAck(const char* cmdName, const char* type, int ca, int ioa, int cot, bool negative)
{
    auto* dataobjects = new vector<Datapoint*>;

    dataobjects->push_back(createCommandAck(type, ca, ioa, cot, negative));

    Reading* reading = new Reading(std::string(cmdName), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    delete reading;
    delete dataobjects;
}

TEST_F(LegacyModeTest, ConnectWhileSouthNotStarted)
{
    iec104Server->registerControl(operateHandler);

    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    // expect operate handler called with "request_connection_status"
    ASSERT_EQ(1, operateHandlerCalled);
    ASSERT_EQ("request_connection_status", calledOperation);

    ASSERT_FALSE(CS104_Connection_connect(connection));

    SendSouthEvent("CONSTAT-1", true, "started", true, "started");

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    SendSouthEvent("CONSTAT-1", false, "started", true, "in progress");

    Thread_sleep(500); 

    SendSouthEvent("CONSTAT-1", false, "started", true, "failed");

    Thread_sleep(500); 

    SendSouthEvent("CONSTAT-1", false, "started", true, "finished");
    
    Thread_sleep(500); 

    SendSouthEvent("CONSTAT-1", true, "not connected", true, "failed");

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_FALSE(CS104_Connection_connect(connection));

    Thread_sleep(500);
}
