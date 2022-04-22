#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iec104.h>

#include <memory>
#include <utility>

#include "cs104_connection.h"
using namespace std;

// Class to be called in each test, contains fixture to be used in
class InterrogationHandlerTest : public testing::Test
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
    }
};

// Test the callback handler for station interrogation
TEST_F(InterrogationHandlerTest, InterrogationHandler)
{
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);
    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        CS104_Connection_sendInterrogationCommand(
            connection, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION);

        struct sCP56Time2a testTimestamp;
        CP56Time2a_createFromMsTimestamp(&testTimestamp, Hal_getTimeInMs());

        CS104_Connection_sendTestCommandWithTimestamp(connection, 1, 0x4938,
                                                      &testTimestamp);

        CS104_Connection_sendInterrogationCommand(
            connection, CS101_COT_ACTIVATION, 1, IEC60870_QOI_GROUP_1);
    }
}
