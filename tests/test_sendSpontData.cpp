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
                "cmd_exec_timeout":5,
                "cmd_recv_timeout":1,
                "accept_cmd_with_time":2
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
                }
            ]
        }
    });

// Class to be called in each test, contains fixture to be used in
class SendSpontDataTest : public testing::Test
{
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

// Test the callback handler for station interrogation
TEST_F(SendSpontDataTest, CreateReading)
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
