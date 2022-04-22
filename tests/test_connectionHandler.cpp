#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iec104.h>

#include <memory>
#include <utility>

#include "cs104_connection.h"
using namespace std;

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

TEST_F(ConnectionHandlerTest, ConnectionHandler)
{
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);
}
