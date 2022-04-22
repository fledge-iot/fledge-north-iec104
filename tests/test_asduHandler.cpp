#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iec104.h>

#include <memory>
#include <utility>

#include "cs104_connection.h"
using namespace std;

// Class to be called in each test, contains fixture to be used in
class AsduHandlerTest : public testing::Test
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

TEST_F(AsduHandlerTest, AsduReceivedHandlerDefault)
{
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);
    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        InformationObject sc =
            (InformationObject)SingleCommand_create(NULL, 5000, true, false, 0);

        CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION,
                                              1, sc);

        InformationObject_destroy(sc);
    }
}

TEST_F(AsduHandlerTest, AsdudHandler_COT_ACTIVATION)
{
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);
    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        InformationObject sc =
            (InformationObject)SingleCommand_create(NULL, 3000, true, false, 0);

        CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION,
                                              1, sc);

        InformationObject_destroy(sc);
    }
}

TEST_F(AsduHandlerTest, AsdudHandler_COT_DEACTIVATION)
{
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);
    if (result)
    {
        CS104_Connection_sendStartDT(connection);

        InformationObject sc =
            (InformationObject)SingleCommand_create(NULL, 5000, true, false, 0);

        CS104_Connection_sendProcessCommandEx(connection,
                                              CS101_COT_DEACTIVATION, 1, sc);

        InformationObject_destroy(sc);
    }
}
