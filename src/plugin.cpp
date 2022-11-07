/*
 * Fledge IEC 104 north plugin.
 *
 * Copyright (c) 2020, RTE (https://www.rte-france.com)
 * 
 * Released under the Apache 2.0 Licence
 *
 * Author: Akli Rahmoun <akli.rahmoun at rte-france.com>
 */
#include <plugin_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string>
#include <logger.h>
#include <plugin_exception.h>
#include <iostream>
#include <config_category.h>
#include <version.h>
#include <iec104.h>


using namespace std;
using namespace rapidjson;

extern "C" {

#define PLUGIN_NAME "iec104"

/**
 * Plugin specific default configuration
 */
static const char* default_config = QUOTE({
	"plugin" : {
		"description" : "IEC 104 Server",
		"type" : "string",
		"default" : PLUGIN_NAME,
		"readonly" : "true"
	},
	"name" : {
		"description" : "The IEC 104 Server name to advertise",
		"type" : "string",
		"default" : "Fledge IEC 104",
		"order" : "1",
		"displayName" : "Server Name"
	},
    "protocol_stack" : {
        "description" : "protocol stack parameters",
        "type" : "JSON",
        "displayName" : "Protocol stack parameters",
        "order" : "2",
        "default" : QUOTE({
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
                    "cmd_dest": "",
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
        })
    },
    "exchanged_data" : {
        "description" : "exchanged data list",
        "type" : "JSON",
        "displayName" : "Exchanged data list",
        "order" : "3",
        "default" : QUOTE({
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
        })
    },
    "tls_conf" : {
        "description" : "tls parameters",
        "type" : "JSON",
        "displayName" : "TLS parameters",
        "order" : "4",
        "default" : QUOTE({      
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
        })
    }
});

/**
 * The IEC 104 plugin interface
 */

/**
 * The C API plugin information structure
 */
static PLUGIN_INFORMATION info = {
	   PLUGIN_NAME,			// Name
	   VERSION,			    // Version
	   SP_CONTROL,		    // Flags
	   PLUGIN_TYPE_NORTH,	// Type
	   "1.0.0",			    // Interface version
	   default_config		// Configuration
};

/**
 * Return the information about this plugin
 */
PLUGIN_INFORMATION *plugin_info()
{
	return &info;
}

/**
 * Initialise the plugin with configuration.
 *
 * This function is called to get the plugin handle.
 */
PLUGIN_HANDLE plugin_init(ConfigCategory* configData)
{
    Logger::getLogger()->info("Initializing the plugin");

	IEC104Server* iec104 = new IEC104Server();

    if (iec104) {
    	iec104->configure(configData);
    }

	return (PLUGIN_HANDLE)iec104;
}

/**
 * Send Readings data to historian server
 */
uint32_t plugin_send(const PLUGIN_HANDLE handle,
		     const vector<Reading *>& readings)
{
	IEC104Server* iec104 = (IEC104Server *)handle;

	return iec104->send(readings);
}


void plugin_register(PLUGIN_HANDLE handle,
		bool ( *write)(const char *name, const char *value, ControlDestination destination, ...),
		int (* operation)(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...))
{
    IEC104Server* iec104 = (IEC104Server*)handle;

    iec104->registerControl(operation);
}

/**
 * Shutdown the plugin
 *
 * Delete allocated data
 *
 * @param handle    The plugin handle
 */
void plugin_shutdown(PLUGIN_HANDLE handle)
{
	IEC104Server* iec104 = (IEC104Server*)handle;

	iec104->stop();

    delete iec104;
}

// End of extern "C"
};
