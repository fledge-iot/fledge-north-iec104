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
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-673",
                          "typeid":"M_SP_NA_1"
                       }
                    ]
                },
                {
                    "label":"TS3",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-674",
                          "typeid":"M_SP_TB_1"
                       }
                    ]
                },
                {
                    "label":"TS4",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-700",
                          "typeid":"M_DP_NA_1"
                       }
                    ]
                },
                {
                    "label":"TS5",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-701",
                          "typeid":"M_DP_TB_1"
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
                       }
                    ]
                },
                {
                    "label":"TM2",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-985",
                          "typeid":"M_ME_NB_1"
                       }
                    ]
                },
                {
                    "label":"TM3",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-986",
                          "typeid":"M_ME_NC_1"
                       }
                    ]
                },
                {
                    "label":"TM4",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-987",
                          "typeid":"M_ME_TD_1"
                       }
                    ]
                },
                {
                    "label":"TM5",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-988",
                          "typeid":"M_ME_TE_1"
                       }
                    ]
                },
                {
                    "label":"TM6",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-989",
                          "typeid":"M_ME_TF_1"
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

    vector<CS101_ASDU> receivedAsdu;

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

        for (CS101_ASDU asdu : receivedAsdu)
        {
            CS101_ASDU_destroy(asdu);
        }

        receivedAsdu.clear();

        iec104Server->stop();

        delete iec104Server;
    }

    static bool test1_ASDUReceivedHandler(void* parameter, int address, CS101_ASDU asdu);
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
    const T value, bool iv, bool bl, bool ov, bool sb, bool nt, CP56Time2a ts)
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

    if (ts) {
         datapoints->push_back(createDatapoint("do_ts", (long)CP56Time2a_toMsTimestamp(ts)));
         datapoints->push_back(createDatapoint("do_ts_iv", (CP56Time2a_isInvalid(ts)) ? 1L : 0L));
         datapoints->push_back(createDatapoint("do_ts_su", (CP56Time2a_isSummerTime(ts)) ? 1L : 0L));
         datapoints->push_back(createDatapoint("do_ts_sub", (CP56Time2a_isSubstituted(ts)) ? 1L : 0L));
    }

    DatapointValue dpv(datapoints, true);

    Datapoint* dp = new Datapoint("data_object", dpv);

    return dp;
}

bool SendSpontDataTest::test1_ASDUReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
    printf("ASDU received - type: %i CA: %i COT: %i\n", CS101_ASDU_getTypeID(asdu), CS101_ASDU_getCA(asdu), CS101_ASDU_getCOT(asdu));

    SendSpontDataTest* self = (SendSpontDataTest*)parameter;
    
    self->receivedAsdu.push_back(CS101_ASDU_clone(asdu, NULL));

    return true;
}


// Test the callback handler for station interrogation
TEST_F(SendSpontDataTest, CreateReading_M_SP_NA_1)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    dataobjects->push_back(createDataObject("M_SP_NA_1", 45, 672, CS101_COT_SPONTANEOUS, (int64_t)1, false, false, false, false, false, NULL));
    dataobjects->push_back(createDataObject("M_SP_NA_1", 45, 673, CS101_COT_SPONTANEOUS, (int64_t)0, false, false, false, false, false, NULL));
    dataobjects->push_back(createDataObject("M_SP_NA_1", 45, 947, CS101_COT_SPONTANEOUS, (int64_t)0, false, false, false, false, false, NULL));

    Reading* reading = new Reading(std::string("TS1"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(1000);

    ASSERT_EQ(2, receivedAsdu.size());

    InformationObject io;
    
    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_SP_NA_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(672, InformationObject_getObjectAddress(io));

    ASSERT_EQ(true, SinglePointInformation_getValue((SinglePointInformation)io));

    InformationObject_destroy(io);

    asdu = receivedAsdu.at(1);

    ASSERT_EQ(M_SP_NA_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(673, InformationObject_getObjectAddress(io));

    ASSERT_EQ(false, SinglePointInformation_getValue((SinglePointInformation)io));

    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_M_SP_TB_1_On)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    struct sCP56Time2a ts;

    uint64_t timeVal = Hal_getTimeInMs();

    CP56Time2a_createFromMsTimestamp(&ts, timeVal);
    CP56Time2a_setInvalid(&ts, true);

    dataobjects->push_back(createDataObject("M_SP_TB_1", 45, 674, CS101_COT_SPONTANEOUS, (int64_t)1, false, false, false, false, false, &ts));

    Reading* reading = new Reading(std::string("TS3"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(1, receivedAsdu.size());

    InformationObject io;

    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_SP_TB_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(674, InformationObject_getObjectAddress(io));
    CP56Time2a rcvdTimestamp = SinglePointWithCP56Time2a_getTimestamp((SinglePointWithCP56Time2a)io);

    ASSERT_EQ(timeVal, CP56Time2a_toMsTimestamp(rcvdTimestamp));

    ASSERT_EQ(true, SinglePointInformation_getValue((SinglePointInformation)io));

    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_M_SP_TB_1_Off)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    struct sCP56Time2a ts;

    uint64_t timeVal = Hal_getTimeInMs();

    CP56Time2a_createFromMsTimestamp(&ts, timeVal);
    CP56Time2a_setInvalid(&ts, true);

    dataobjects->push_back(createDataObject("M_SP_TB_1", 45, 674, CS101_COT_SPONTANEOUS, (int64_t)0, false, false, false, false, false, &ts));

    Reading* reading = new Reading(std::string("TS3"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(1, receivedAsdu.size());

    InformationObject io;

    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_SP_TB_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(674, InformationObject_getObjectAddress(io));
    CP56Time2a rcvdTimestamp = SinglePointWithCP56Time2a_getTimestamp((SinglePointWithCP56Time2a)io);

    ASSERT_EQ(timeVal, CP56Time2a_toMsTimestamp(rcvdTimestamp));

    ASSERT_EQ(false, SinglePointInformation_getValue((SinglePointInformation)io));

    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_M_DP_NA_1)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    dataobjects->push_back(createDataObject("M_DP_NA_1", 45, 700, CS101_COT_SPONTANEOUS, (int64_t)0, false, false, false, false, false, NULL));
    dataobjects->push_back(createDataObject("M_DP_NA_1", 45, 700, CS101_COT_SPONTANEOUS, (int64_t)1, true, false, false, false, true, NULL));
    dataobjects->push_back(createDataObject("M_DP_NA_1", 45, 700, CS101_COT_SPONTANEOUS, (int64_t)2, false, false, false, true, false, NULL));
    dataobjects->push_back(createDataObject("M_DP_NA_1", 45, 700, CS101_COT_SPONTANEOUS, (int64_t)3, false, true, false, false, false, NULL));
    dataobjects->push_back(createDataObject("M_SP_NA_1", 45, 812, CS101_COT_SPONTANEOUS, (int64_t)0, false, false, false, false, false, NULL));

    Reading* reading = new Reading(std::string("TS3"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(4, receivedAsdu.size());

    InformationObject io;
    
    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_DP_NA_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(700, InformationObject_getObjectAddress(io));

    ASSERT_EQ(0, DoublePointInformation_getValue((DoublePointInformation)io));

    InformationObject_destroy(io);

    asdu = receivedAsdu.at(1);

    ASSERT_EQ(M_DP_NA_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(700, InformationObject_getObjectAddress(io));

    ASSERT_EQ(IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL, DoublePointInformation_getQuality((DoublePointInformation)io));

    ASSERT_EQ(1, DoublePointInformation_getValue((DoublePointInformation)io));

    InformationObject_destroy(io);

    asdu = receivedAsdu.at(2);

    ASSERT_EQ(M_DP_NA_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(700, InformationObject_getObjectAddress(io));

    ASSERT_EQ(IEC60870_QUALITY_SUBSTITUTED, DoublePointInformation_getQuality((DoublePointInformation)io));

    ASSERT_EQ(2, DoublePointInformation_getValue((DoublePointInformation)io));

    InformationObject_destroy(io);

    asdu = receivedAsdu.at(3);

    ASSERT_EQ(M_DP_NA_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(700, InformationObject_getObjectAddress(io));

    ASSERT_EQ(IEC60870_QUALITY_BLOCKED, DoublePointInformation_getQuality((DoublePointInformation)io));

    ASSERT_EQ(3, DoublePointInformation_getValue((DoublePointInformation)io));

    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_M_DP_TB_1)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    struct sCP56Time2a ts;

    uint64_t timeVal = Hal_getTimeInMs();

    CP56Time2a_createFromMsTimestamp(&ts, timeVal);
    CP56Time2a_setInvalid(&ts, true);

    dataobjects->push_back(createDataObject("M_DP_TB_1", 45, 701, CS101_COT_SPONTANEOUS, (int64_t)2, false, false, false, false, false, &ts));
    dataobjects->push_back(createDataObject("M_DP_TB_1", 45, 700, CS101_COT_SPONTANEOUS, (int64_t)2, false, false, false, false, false, &ts));
    dataobjects->push_back(createDataObject("M_SP_TB_1", 45, 700, CS101_COT_SPONTANEOUS, (int64_t)2, false, false, false, false, false, &ts));

    Reading* reading = new Reading(std::string("TS5"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(2, receivedAsdu.size());

    InformationObject io;

    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_DP_TB_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(701, InformationObject_getObjectAddress(io));
    CP56Time2a rcvdTimestamp = DoublePointWithCP56Time2a_getTimestamp((DoublePointWithCP56Time2a)io);

    ASSERT_EQ(timeVal, CP56Time2a_toMsTimestamp(rcvdTimestamp));

    InformationObject_destroy(io);

    asdu = receivedAsdu.at(1);

    ASSERT_EQ(M_DP_TB_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(700, InformationObject_getObjectAddress(io));
    rcvdTimestamp = DoublePointWithCP56Time2a_getTimestamp((DoublePointWithCP56Time2a)io);

    ASSERT_EQ(timeVal, CP56Time2a_toMsTimestamp(rcvdTimestamp));

    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_M_ME_NA_1)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    dataobjects->push_back(createDataObject("M_ME_NA_1", 45, 984, CS101_COT_SPONTANEOUS, (float)0.1f, false, false, false, false, false, NULL));
    dataobjects->push_back(createDataObject("M_ME_NA_1", 45, 984, CS101_COT_SPONTANEOUS, (float)1.0f, false, false, true, false, false, NULL));

    Reading* reading = new Reading(std::string("TM1"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(2, receivedAsdu.size());

    InformationObject io;
    
    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_ME_NA_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(984,InformationObject_getObjectAddress(io));
    ASSERT_NEAR(0.1f, MeasuredValueNormalized_getValue((MeasuredValueNormalized)io), 0.01f);

    InformationObject_destroy(io);

    asdu = receivedAsdu.at(1);

    ASSERT_EQ(M_ME_NA_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(984,InformationObject_getObjectAddress(io));
    ASSERT_EQ(IEC60870_QUALITY_OVERFLOW, MeasuredValueNormalized_getQuality((MeasuredValueNormalized)io));
    ASSERT_NEAR(1.0f, MeasuredValueNormalized_getValue((MeasuredValueNormalized)io), 0.01f);

    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_M_ME_NB_1)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    dataobjects->push_back(createDataObject("M_ME_NB_1", 45, 985, CS101_COT_SPONTANEOUS, (int64_t)-1234, false, false, false, false, false, NULL));

    Reading* reading = new Reading(std::string("TM2"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(1, receivedAsdu.size());

    InformationObject io;
    
    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_ME_NB_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(985,InformationObject_getObjectAddress(io));
    ASSERT_EQ(-1234, MeasuredValueScaled_getValue((MeasuredValueScaled)io));
    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_M_ME_NC_1)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    dataobjects->push_back(createDataObject("M_ME_NC_1", 45, 986, CS101_COT_SPONTANEOUS, (float)-0.01f, false, false, false, false, false, NULL));

    Reading* reading = new Reading(std::string("TM3"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(1, receivedAsdu.size());

    InformationObject io;
    
    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_ME_NC_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(986,InformationObject_getObjectAddress(io));
    ASSERT_NEAR(-0.01f, MeasuredValueShort_getValue((MeasuredValueShort)io), 0.001f);
    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_M_ME_TD_1)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    struct sCP56Time2a ts;

    uint64_t timeVal = Hal_getTimeInMs();

    CP56Time2a_createFromMsTimestamp(&ts, timeVal);
    CP56Time2a_setInvalid(&ts, true);

    dataobjects->push_back(createDataObject("M_ME_TD_1", 45, 987, CS101_COT_SPONTANEOUS, (float)-0.1f, false, false, false, false, false, &ts));

    Reading* reading = new Reading(std::string("TM4"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(1, receivedAsdu.size());

    InformationObject io;

    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_ME_TD_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(987, InformationObject_getObjectAddress(io));
    CP56Time2a rcvdTimestamp = MeasuredValueNormalizedWithCP56Time2a_getTimestamp((MeasuredValueNormalizedWithCP56Time2a)io);

    ASSERT_EQ(timeVal, CP56Time2a_toMsTimestamp(rcvdTimestamp));

    ASSERT_NEAR(-0.1f, MeasuredValueNormalized_getValue((MeasuredValueNormalized)io), 0.01f);

    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_M_ME_TE_1)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    struct sCP56Time2a ts;

    uint64_t timeVal = Hal_getTimeInMs();

    CP56Time2a_createFromMsTimestamp(&ts, timeVal);
    CP56Time2a_setInvalid(&ts, true);

    dataobjects->push_back(createDataObject("M_ME_TE_1", 45, 988, CS101_COT_SPONTANEOUS, (int64_t)1000, false, false, false, false, false, &ts));

    Reading* reading = new Reading(std::string("TM5"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(1, receivedAsdu.size());

    InformationObject io;

    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_ME_TE_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(988, InformationObject_getObjectAddress(io));
    CP56Time2a rcvdTimestamp = MeasuredValueScaledWithCP56Time2a_getTimestamp((MeasuredValueScaledWithCP56Time2a)io);

    ASSERT_EQ(timeVal, CP56Time2a_toMsTimestamp(rcvdTimestamp));

    ASSERT_EQ(1000, MeasuredValueScaled_getValue((MeasuredValueScaled)io));

    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_M_ME_TF_1)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    struct sCP56Time2a ts;

    uint64_t timeVal = Hal_getTimeInMs();

    CP56Time2a_createFromMsTimestamp(&ts, timeVal);
    CP56Time2a_setInvalid(&ts, true);

    dataobjects->push_back(createDataObject("M_ME_TF_1", 45, 989, CS101_COT_SPONTANEOUS, (float)2.f, false, false, false, false, false, &ts));
    dataobjects->push_back(createDataObject("M_ME_TF_1", 45, 989, CS101_COT_SPONTANEOUS, (float)99.f, true, false, true, false, false, &ts));

    Reading* reading = new Reading(std::string("TM6"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(2, receivedAsdu.size());

    InformationObject io;

    CS101_ASDU asdu = receivedAsdu.at(0);

    ASSERT_EQ(M_ME_TF_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(989, InformationObject_getObjectAddress(io));
    CP56Time2a rcvdTimestamp = MeasuredValueShortWithCP56Time2a_getTimestamp((MeasuredValueShortWithCP56Time2a)io);

    ASSERT_EQ(timeVal, CP56Time2a_toMsTimestamp(rcvdTimestamp));

    ASSERT_NEAR(2.f, MeasuredValueShort_getValue((MeasuredValueShort)io), 0.001f);

    InformationObject_destroy(io);

    asdu = receivedAsdu.at(1);

    ASSERT_EQ(M_ME_TF_1, CS101_ASDU_getTypeID(asdu));
    ASSERT_EQ(45, CS101_ASDU_getCA(asdu));
    ASSERT_EQ(1, CS101_ASDU_getNumberOfElements(asdu));

    io = CS101_ASDU_getElement(asdu, 0);
    ASSERT_EQ(989, InformationObject_getObjectAddress(io));
    rcvdTimestamp = MeasuredValueShortWithCP56Time2a_getTimestamp((MeasuredValueShortWithCP56Time2a)io);

    ASSERT_EQ(timeVal, CP56Time2a_toMsTimestamp(rcvdTimestamp));

    ASSERT_EQ(IEC60870_QUALITY_INVALID | IEC60870_QUALITY_OVERFLOW, MeasuredValueShort_getQuality((MeasuredValueShort)io));

    ASSERT_NEAR(99.f, MeasuredValueShort_getValue((MeasuredValueShort)io), 0.001f);

    InformationObject_destroy(io);

    delete reading;

    delete dataobjects;
}

TEST_F(SendSpontDataTest, CreateReading_differentSpontaneousCOTs)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    CS104_Connection_setASDUReceivedHandler(connection, test1_ASDUReceivedHandler, this);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_sendStartDT(connection);

    auto* dataobjects = new vector<Datapoint*>;

    dataobjects->push_back(createDataObject("M_ME_NA_1", 45, 984, CS101_COT_SPONTANEOUS, (float)0.1f, false, false, false, false, false, NULL));
    dataobjects->push_back(createDataObject("M_ME_NA_1", 45, 984, CS101_COT_BACKGROUND_SCAN, (float)1.0f, false, false, true, false, false, NULL));
    dataobjects->push_back(createDataObject("M_ME_NA_1", 45, 984, CS101_COT_PERIODIC, (float)1.0f, false, false, true, false, false, NULL));
    dataobjects->push_back(createDataObject("M_ME_NA_1", 45, 984, CS101_COT_RETURN_INFO_LOCAL, (float)1.0f, false, false, true, false, false, NULL));
    dataobjects->push_back(createDataObject("M_ME_NA_1", 45, 984, CS101_COT_RETURN_INFO_REMOTE, (float)1.0f, false, false, true, false, false, NULL));
    dataobjects->push_back(createDataObject("M_ME_NA_1", 45, 984, CS101_COT_INTERROGATED_BY_STATION, (float)1.0f, false, false, true, false, false, NULL));

    Reading* reading = new Reading(std::string("TM1"), *dataobjects);

    vector<Reading*> readings;

    readings.push_back(reading);

    iec104Server->send(readings);

    Thread_sleep(500);

    ASSERT_EQ(5, receivedAsdu.size());

    delete reading;

    delete dataobjects;
}
