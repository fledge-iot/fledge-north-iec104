#include <gtest/gtest.h>

#include <plugin_api.h>

extern "C" {
	PLUGIN_INFORMATION *plugin_info();
};

TEST(IEC104, PluginInfo)
{
	PLUGIN_INFORMATION *info = plugin_info();
	ASSERT_STREQ(info->name, "iec104");
	ASSERT_EQ(info->type, PLUGIN_TYPE_NORTH);
}

