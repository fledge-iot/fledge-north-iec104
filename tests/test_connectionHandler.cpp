#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iec104.h>

#include <memory>
#include <utility>

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
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
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
    
static string protocol_stack_2 = QUOTE({
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
                "tls":true,
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
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
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
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1"
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
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
                },
                {
                    "cert_file": "iec104_ca2.cer"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "iec104_client.cer"
                }
            ]
        }
    });

static string tls_2 = QUOTE({
        "tls_conf" : {
            "private_key" : "iec104_server.key",
            "own_cert" : "iec104_server.cer",
            "remote_certs" : [
                {
                    "cert_file": "iec104_client.cer"
                }
            ]
        }
    });

static string tls_3 = QUOTE({
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

static string tls_4 = QUOTE({
        "tls_conf" : {
            "private_key" : "iec104_server.key",
            "own_cert" : "iec104_server.cer"
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
class ConnectionHandlerTest : public testing::Test
{
protected:
    IEC104Server* iec104Server;  // Object on which we call for tests
    CS104_Connection connection;
    // Setup is ran for every tests, so each variable are reinitialised
    void SetUp() override
    {
        // Init iec104server object
        iec104Server = new IEC104Server();
    }

    // TearDown is ran for every tests, so each variable are destroyed again
    void TearDown() override
    {
        iec104Server->stop();

        delete iec104Server;
    }
};

TEST_F(ConnectionHandlerTest, NormalConnection)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    // Create connection
    connection = CS104_Connection_create("127.0.0.1", IEC_60870_5_104_DEFAULT_PORT);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
}

TEST_F(ConnectionHandlerTest, TLSConnection)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionNoCaCertificate)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_2);

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionNoRemoteOrCaCertificate)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_4);

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}