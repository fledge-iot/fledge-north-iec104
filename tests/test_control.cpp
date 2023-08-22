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
                "mode": "accept_always"
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
                },
                {
                    "label":"CM2",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-14005",
                          "typeid":"C_DC_NA_1",
                          "termination_timeout": 3000
                       }
                    ]
                },
                {
                    "label":"CM3",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-16005",
                          "typeid":"C_RC_NA_1",
                          "termination_timeout": 3000
                       }
                    ]
                },
                {
                    "label":"CM4",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-18005",
                          "typeid":"C_SE_NA_1",
                          "termination_timeout": 3000
                       }
                    ]
                },
                {
                    "label":"CM5",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-20005",
                          "typeid":"C_SE_NB_1",
                          "termination_timeout": 3000
                       }
                    ]
                },
                {
                    "label":"CM6",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-22005",
                          "typeid":"C_SE_NC_1",
                          "termination_timeout": 3000
                       }
                    ]
                },
                {
                    "label":"IEC104Command",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-23005",
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
                },
                {
                    "label":"IEC104Command",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-24005",
                          "typeid":"C_SE_TC_1",
                          "termination_timeout": 1
                       }
                    ]
                }
            ]
        }
    });

static string exchanged_data_3 = QUOTE({
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
                    "label":"IEC104Command",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-24005",
                          "typeid":"C_SC_TA_1"
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
        requestSouthStatusCalled = 0;
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
    static int requestSouthStatusCalled;

    static int operateHandler(char *operation, int paramCount, char* names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerSingleCommand(char *operation, int paramCount, char* names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerReceiveSetpointCommandShortWithTimestamp(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerReceiveSetpointCommandShortWithInvalidTimestamp(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerSinglePointCommandUnknownCA(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerReceiveUnexpectedDoublePointCommand(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerCommandAckTimeout(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerCommandActCon(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerCommandActConNegative(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerSinglePointCommandIOMissing(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerReceiveSinglePointCommandWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerDoublePointCommand(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerDoublePointCommandWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerMultipleSinglePointCommandWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerStepPointCommand(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerStepPointCommandWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerSetPointCommandNormalized(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerSetPointCommandNormalizedWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerSetPointCommandScaled(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerSetPointCommandScaledWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);
    static int operateHandlerSetPointCommandShort(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...);

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

    static bool m_asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu);
};

bool
ControlTest::m_asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
    ControlTest* self = (ControlTest*)parameter;

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

int ControlTest::operateHandlerCalled;
int ControlTest::requestSouthStatusCalled;

int ControlTest::operateHandler(char *operation, int paramCount, char* names[], char *parameters[], ControlDestination destination, ...)
{
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerSingleCommand(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SC_NA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(23005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_EQ(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(1));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerReceiveSetpointCommandShortWithTimestamp(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SE_TC_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(24005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_NE(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(1.5f));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerReceiveSetpointCommandShortWithInvalidTimestamp(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    EXPECT_EQ(operation,"request_connection_status");
    if(!strcmp(operation, "IEC104Command")) {
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerSinglePointCommandUnknownCA(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    EXPECT_EQ(operation,"request_connection_status");
    if(!strcmp(operation, "IEC104Command")) {
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerReceiveUnexpectedDoublePointCommand(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    EXPECT_EQ(operation,"request_connection_status");
    if(!strcmp(operation, "IEC104Command")) {
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerCommandAckTimeout(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SC_NA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(10005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_EQ(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(1));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerCommandActCon(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SC_NA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(10005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_EQ(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(1));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerCommandActConNegative(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SC_NA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(10005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_EQ(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(1));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerSinglePointCommandIOMissing(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    EXPECT_EQ(operation,"request_connection_status");
    if(!strcmp(operation, "IEC104Command")) {
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerReceiveSinglePointCommandWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...) {
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SC_TA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(10005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_NE(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(1));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerDoublePointCommand(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...) {
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_DC_NA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(14005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_EQ(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(1));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerDoublePointCommandWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...) {
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_DC_TA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(14005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_NE(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(1));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerMultipleSinglePointCommandWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SC_TA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(10005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_NE(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(1));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerStepPointCommand(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_RC_NA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(16005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_EQ(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(0));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerStepPointCommandWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_RC_TA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(16005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_NE(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(0));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerSetPointCommandNormalized(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SE_NA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(18005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_EQ(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(0.000015));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerSetPointCommandNormalizedWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SE_TA_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(18005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_NE(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(0.000015));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerSetPointCommandScaled(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SE_NB_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(20005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_EQ(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(0));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerSetPointCommandScaledWithTime(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SE_TB_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(20005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_NE(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(0));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

    return 1;
}

int ControlTest::operateHandlerSetPointCommandShort(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...)
{
    printf("%s\n",operation);
    if(!strcmp(operation, "IEC104Command")) {
        EXPECT_EQ(9,paramCount);
        printf("PARAM COUNT: %d\n", paramCount);
        EXPECT_EQ(names[0],"co_type");
        EXPECT_EQ(0,strcmp(parameters[0],"C_SE_NC_1"));
        EXPECT_EQ(names[1],"co_ca");
        EXPECT_EQ(parameters[1],to_string(45));
        EXPECT_EQ(names[2],"co_ioa");
        EXPECT_EQ(parameters[2],to_string(22005));
        EXPECT_EQ(names[3],"co_cot");
        EXPECT_EQ(parameters[3],to_string(7));
        EXPECT_EQ(names[4],"co_negative");
        EXPECT_EQ(parameters[4],to_string(0));
        EXPECT_EQ(names[5],"co_se");
        EXPECT_EQ(parameters[5],to_string(0));
        EXPECT_EQ(names[6],"co_test");
        EXPECT_EQ(parameters[6],to_string(0));
        EXPECT_EQ(names[7],"co_ts");
        EXPECT_EQ(parameters[7],"");
        EXPECT_EQ(names[8],"co_value");
        EXPECT_EQ(parameters[8],to_string(0.0f));
        for(int i = 0; i < paramCount; i++) {
            printf("PARAM: %s: %s\n", names[i], parameters[i]);
        }

    }
    if (!strcmp(operation, "request_connection_status")) {
        requestSouthStatusCalled++;
    }
    else {
        operateHandlerCalled++;
    }

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

void
ControlTest::ForwardCommandAck(const char* cmdName, const char* type, int ca, int ioa, int cot, bool negative)
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

    iec104Server->registerControl(operateHandlerSingleCommand);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject sc = (InformationObject)SingleCommand_create(NULL, 23005, true, false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);
}

TEST_F(ControlTest, ReceiveSetpointCommandShortWithTimestamp)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data_2, tls);

    iec104Server->registerControl(operateHandlerReceiveSetpointCommandShortWithTimestamp);

    iec104Server->ActConTimeout(200);
    iec104Server->ActTermTimeout(200);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs());

    InformationObject sc = (InformationObject)SetpointCommandShortWithCP56Time2a_create(NULL, 24005, 1.5f, false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    free(timestamp);

    Thread_sleep(1500);

    ASSERT_EQ(1, operateHandlerCalled);
}

TEST_F(ControlTest, ReceiveSetpointCommandShortWithInvalidTimestamp)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data_2, tls);

    iec104Server->registerControl(operateHandlerReceiveSetpointCommandShortWithInvalidTimestamp);

    iec104Server->ActConTimeout(200);
    iec104Server->ActTermTimeout(200);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, 0);

    InformationObject sc = (InformationObject)SetpointCommandShortWithCP56Time2a_create(NULL, 24005, 1.5f, false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    free(timestamp);

    Thread_sleep(1500);

    /* expect the command to be ignored */
    ASSERT_EQ(0, operateHandlerCalled);

    /* expect negative ACT-CON */
    ASSERT_EQ(1, asduHandlerCalled);
    ASSERT_EQ(1, actConReceived);
    ASSERT_TRUE(actConNegative);
}



TEST_F(ControlTest, SinglePointCommandUnknownCA)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerSinglePointCommandUnknownCA);

    Thread_sleep(500); /* wait for the server to start */

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

    iec104Server->registerControl(operateHandlerReceiveUnexpectedDoublePointCommand);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject sc = (InformationObject)DoubleCommand_create(NULL, 10005, 1, false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(500);

    ASSERT_EQ(0, operateHandlerCalled);
}

TEST_F(ControlTest, CommandAckTimeout)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerCommandAckTimeout);

    iec104Server->ActConTimeout(200);
    iec104Server->ActTermTimeout(200);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject sc = (InformationObject)SingleCommand_create(NULL, 10005, true, false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(1000);

    ASSERT_EQ(1, operateHandlerCalled);
}

TEST_F(ControlTest, CommandActCon)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerCommandActCon);

    Thread_sleep(500); /* wait for the server to start */

    iec104Server->ActConTimeout(1000);
    iec104Server->ActTermTimeout(1000);

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject sc = (InformationObject)SingleCommand_create(NULL, 10005, true, false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(200);

    ASSERT_EQ(1, operateHandlerCalled);

    // forward ACT-CON from south side
    ForwardCommandAck("CM1", "C_SC_NA_1", 45, 10005, CS101_COT_ACTIVATION_CON, false);

    Thread_sleep(200);

    // forward ACT-TERM from south side
    ForwardCommandAck("CM1", "C_SC_NA_1", 45, 10005, CS101_COT_ACTIVATION_TERMINATION, false);

    Thread_sleep(1000);

    ASSERT_EQ(2, asduHandlerCalled);
    ASSERT_EQ(1, actConReceived);
    ASSERT_FALSE(actConNegative);
    ASSERT_EQ(1, actTermReceived);
}

TEST_F(ControlTest, CommandActConNegative)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerCommandActConNegative);

    iec104Server->ActConTimeout(1000);
    iec104Server->ActTermTimeout(1000);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject sc = (InformationObject)SingleCommand_create(NULL, 10005, true, false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(200);

    ASSERT_EQ(1, operateHandlerCalled);

    // forward ACT-CON from south side
    ForwardCommandAck("CM1", "C_SC_NA_1", 45, 10005, CS101_COT_ACTIVATION_CON, true);

    Thread_sleep(200);

    ASSERT_EQ(1, asduHandlerCalled);
    ASSERT_EQ(1, actConReceived);
    ASSERT_TRUE(actConNegative);
    ASSERT_EQ(0, actTermReceived);
}

TEST_F(ControlTest, SinglePointCommandIOMissing)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerSinglePointCommandIOMissing);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    CS101_AppLayerParameters alParams = CS104_Connection_getAppLayerParameters(connection);

    CS101_ASDU asdu = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION, 0, 45, false, false);

    CS101_ASDU_setTypeID(asdu, C_SC_NA_1);

    CS104_Connection_sendASDU(connection, asdu);

    CS101_ASDU_destroy(asdu);

    Thread_sleep(500);

    ASSERT_EQ(0, operateHandlerCalled);
}

TEST_F(ControlTest, ReceiveSinglePointCommandWithTime)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerReceiveSinglePointCommandWithTime);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs());

    InformationObject sc = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);

    /* wait for time to become to old for configured cmd_exec_timeout parameter */
    Thread_sleep(1200);

    sc = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);

    free(timestamp);
}

TEST_F(ControlTest, ReceiveDoublePointCommand)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerDoublePointCommand);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject sc = (InformationObject)DoubleCommand_create(NULL, 14005, 1, false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);
}

TEST_F(ControlTest, ReceiveDoublePointCommandWithTime)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerDoublePointCommandWithTime);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs());

    InformationObject sc = (InformationObject)DoubleCommandWithCP56Time2a_create(NULL, 14005, true, false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);

    /* wait for time to become to old for configured cmd_exec_timeout parameter */
    Thread_sleep(1200);

    sc = (InformationObject)DoubleCommandWithCP56Time2a_create(NULL, 14005, true, false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);

    free(timestamp);
}


TEST_F(ControlTest, ReceiveMultipleSinglePointCommandWithTime)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerMultipleSinglePointCommandWithTime);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs());

    InformationObject sc1 = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);
    InformationObject sc2 = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);
    InformationObject sc3 = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);
    InformationObject sc4 = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);
    InformationObject sc5 = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc1);
    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc2);
    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc3);
    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc4);
    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc5);

    InformationObject_destroy(sc1);
    InformationObject_destroy(sc2);
    InformationObject_destroy(sc3);
    InformationObject_destroy(sc4);
    InformationObject_destroy(sc5);

    Thread_sleep(500);

    ASSERT_EQ(5, operateHandlerCalled);

    /* wait for time to become to old for configured cmd_exec_timeout parameter */
    Thread_sleep(1200);

    sc1 = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);
    sc2 = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);
    sc3 = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);
    sc4 = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);
    sc5 = (InformationObject)SingleCommandWithCP56Time2a_create(NULL, 10005, true, false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc1);
    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc2);
    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc3);
    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc4);
    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc5);

    InformationObject_destroy(sc1);
    InformationObject_destroy(sc2);
    InformationObject_destroy(sc3);
    InformationObject_destroy(sc4);
    InformationObject_destroy(sc5);

    Thread_sleep(500);

    ASSERT_EQ(5, operateHandlerCalled);

    free(timestamp);
}

TEST_F(ControlTest, ReceiveStepPointCommand)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerStepPointCommand);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject rc = (InformationObject)StepCommand_create(NULL, 16005, IEC60870_STEP_INVALID_0 , false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, rc);

    InformationObject_destroy(rc);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);
}


TEST_F(ControlTest, ReceiveStepPointCommandWithTime)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerStepPointCommandWithTime);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs());

    InformationObject rc = (InformationObject)StepCommandWithCP56Time2a_create(NULL, 16005, IEC60870_STEP_INVALID_0 , false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, rc);

    InformationObject_destroy(rc);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);

    /* wait for time to become to old for configured cmd_exec_timeout parameter */
    Thread_sleep(1200);

    rc = (InformationObject)StepCommandWithCP56Time2a_create(NULL, 14005, IEC60870_STEP_INVALID_0 , false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, rc);

    InformationObject_destroy(rc);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);

    free(timestamp);
}

TEST_F(ControlTest, ReceiveSetPointCommandNormalized)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerSetPointCommandNormalized);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject se = (InformationObject)SetpointCommandNormalized_create(NULL, 18005, 0 , false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, se);

    InformationObject_destroy(se);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);
}

TEST_F(ControlTest, ReceiveSetPointCommandNormalizedWithTime)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerSetPointCommandNormalizedWithTime);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs());

    InformationObject se = (InformationObject)SetpointCommandNormalizedWithCP56Time2a_create(NULL, 18005, 0 , false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, se);

    InformationObject_destroy(se);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);

    /* wait for time to become to old for configured cmd_exec_timeout parameter */
    Thread_sleep(1200);

    se = (InformationObject)SetpointCommandNormalizedWithCP56Time2a_create(NULL, 18005, 0 , false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, se);

    InformationObject_destroy(se);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);

    free(timestamp);
}


TEST_F(ControlTest, ReceiveSetPointCommandScaled)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerSetPointCommandScaled);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject se = (InformationObject)SetpointCommandScaled_create(NULL, 20005, 0 , false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, se);

    InformationObject_destroy(se);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);
}


TEST_F(ControlTest, ReceiveSetPointCommandScaledWithTime)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerSetPointCommandScaledWithTime);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    CP56Time2a timestamp = CP56Time2a_createFromMsTimestamp(NULL, Hal_getTimeInMs());

    InformationObject se = (InformationObject)SetpointCommandScaledWithCP56Time2a_create(NULL, 20005, 0 , false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, se);

    InformationObject_destroy(se);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);

    /* wait for time to become to old for configured cmd_exec_timeout parameter */
    Thread_sleep(1200);

    se = (InformationObject)SetpointCommandScaledWithCP56Time2a_create(NULL, 20005, 0 , false, 0, timestamp);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, se);

    InformationObject_destroy(se);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);

    free(timestamp);
}

TEST_F(ControlTest, ReceiveSetPointCommandShort)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    iec104Server->registerControl(operateHandlerSetPointCommandShort);

    Thread_sleep(500); /* wait for the server to start */

    ASSERT_TRUE(CS104_Connection_connect(connection));

    CS104_Connection_sendStartDT(connection);

    InformationObject se = (InformationObject)SetpointCommandShort_create(NULL, 22005, 0 , false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, se);

    InformationObject_destroy(se);

    Thread_sleep(500);

    ASSERT_EQ(1, operateHandlerCalled);
}
