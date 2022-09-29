#include <gtest/gtest.h>
#include <plugin_api.h>
#include <string.h>
#include <string>
#include <rapidjson/document.h>

using namespace std;
using namespace rapidjson;

extern "C" {
	PLUGIN_INFORMATION *plugin_info();
};

TEST(IEC104, PluginInfo)
{
	PLUGIN_INFORMATION *info = plugin_info();
	ASSERT_STREQ(info->name, "iec104");
	ASSERT_EQ(info->type, PLUGIN_TYPE_NORTH);
}

