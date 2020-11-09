/*
 * Fledge IEC 104 north plugin.
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Akli Rahmoun
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
const char *default_config = QUOTE({
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
	   0,				    // Flags
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

	IEC104Server *iec104 = new IEC104Server();
	iec104->configure(configData);

	return (PLUGIN_HANDLE)iec104;
}

/**
 * Send Readings data to historian server
 */
uint32_t plugin_send(const PLUGIN_HANDLE handle,
		     const vector<Reading *>& readings)
{
	IEC104Server *iec104 = (IEC104Server *)handle;

	return iec104->send(readings);
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
	IEC104Server *iec104 = (IEC104Server *)handle;

	iec104->stop();
        delete iec104;
}

// End of extern "C"
};
