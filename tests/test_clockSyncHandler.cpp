#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iec104.h>

#include <memory>
#include <utility>

#include "cs104_connection.h"
using namespace std;

// Class to be called in each test, contains fixture to be used in
class ClockSyncHandlerTest : public testing::Test
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

TEST_F(ClockSyncHandlerTest, clockSyncHandler)
{
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);
    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        /* Send clock synchronization command */
        struct sCP56Time2a newTime;

        CP56Time2a_createFromMsTimestamp(&newTime, Hal_getTimeInMs());
        Thread_sleep(1000);

        CS104_Connection_sendClockSyncCommand(connection, 1, &newTime);
    }
}
