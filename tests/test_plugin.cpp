#include <config_category.h>
#include <gtest/gtest.h>
#include <iec104.h>
#include <plugin_api.h>
#include <rapidjson/document.h>

#include <string>

using namespace std;
using namespace rapidjson;

typedef void (*INGEST_CB)(void *, Reading);

extern "C"
{
    PLUGIN_HANDLE plugin_init(ConfigCategory *config);
    void plugin_register(PLUGIN_HANDLE handle,
		bool ( *write)(const char *name, const char *value, ControlDestination destination, ...),
		int (* operation)(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...));
    void plugin_shutdown(PLUGIN_HANDLE handle);
    uint32_t plugin_send(const PLUGIN_HANDLE handle,
		     const vector<Reading *>& readings);
    PLUGIN_INFORMATION *plugin_info();

};

#define PROTOCOL_TRANSLATION_DEF \
    QUOTE({"protocol_translation" : {"name" : "test_pt"}})

#define PROTOCOL_STACK_DEF QUOTE({"protocol_stack" : {"name" : "test_ps"}})

#define EXCHANGED_DATA_DEF QUOTE({"exchanged_data" : {"name" : "test_ed"}})

#define TLS_DEF QUOTE({"tls_conf" : {"name" : "test_tls"}})

static const char *default_config = QUOTE({
    "plugin" : {
        "description" : "iec104 north plugin",
        "type" : "string",
        "default" : "TEST_PLUGIN",
        "readonly" : "true"
    },

    "asset" : {
        "description" : "Asset name",
        "type" : "string",
        "default" : "iec104_TEST",
        "displayName" : "Asset Name",
        "order" : "1",
        "mandatory" : "true"
    },

    "protocol_stack" : {
        "description" : "protocol stack parameters",
        "type" : "string",
        "displayName" : "Protocol stack parameters",
        "order" : "2",
        "default" : PROTOCOL_STACK_DEF
    },

    "exchanged_data" : {
        "description" : "exchanged data list",
        "type" : "string",
        "displayName" : "Exchanged data list",
        "order" : "3",
        "default" : EXCHANGED_DATA_DEF
    },

    "tls" : {
        "description" : "tls parameters",
        "type" : "string",
        "displayName" : "TLS parameters",
        "order" : "5",
        "default" : TLS_DEF
    }
});

TEST(PluginTest, PluginInit)
{
    ConfigCategory *config = new ConfigCategory("Test_Config", default_config);
    config->setItemsValueFromDefault();

    PLUGIN_HANDLE handle = nullptr;

    ASSERT_NO_THROW(handle = plugin_init(config));
    
    if (handle != nullptr) plugin_shutdown((PLUGIN_HANDLE*)handle);

    ConfigCategory *emptyConfig = new ConfigCategory();
    ASSERT_NO_THROW(handle = plugin_init(emptyConfig));

    if (handle != nullptr) plugin_shutdown((PLUGIN_HANDLE*)handle);

    // ConfigCategory *nullConfig;

    // ASSERT_THROW(handle = plugin_init(nullConfig),exception);

    delete config;
    delete emptyConfig;
}



TEST(PluginTest, PluginInfo)
{
	PLUGIN_INFORMATION *info = plugin_info();
	ASSERT_STREQ(info->name, "iec104");
	ASSERT_EQ(info->type, PLUGIN_TYPE_NORTH);
}


static int PluginRegisterTest_operation(char *operation, int paramCount, char *names[], char *parameters[], ControlDestination destination, ...){
    return 0;
}


TEST(PluginTest, PluginRegister)
{
    ConfigCategory *emptyConfig = new ConfigCategory();
    PLUGIN_HANDLE handle = plugin_init(emptyConfig);
    
    ASSERT_NO_THROW(
        plugin_register((PLUGIN_HANDLE*)handle, NULL,PluginRegisterTest_operation));

    plugin_shutdown((PLUGIN_HANDLE*)handle);

    delete emptyConfig;
}

TEST(PluginTest, PluginSend)
{
    ConfigCategory *emptyConfig = new ConfigCategory();
    PLUGIN_HANDLE handle = plugin_init(emptyConfig);
    vector<Reading *> readings;
    ASSERT_NO_THROW(plugin_send((PLUGIN_HANDLE *)handle, readings));

    delete emptyConfig;
}

TEST(PluginTest, PluginStop)
{
    ConfigCategory *emptyConfig = new ConfigCategory();
    PLUGIN_HANDLE handle = plugin_init(emptyConfig);
    ASSERT_NO_THROW(plugin_shutdown((PLUGIN_HANDLE *)handle)); 

    delete emptyConfig;
}