#include "iec104.h"

#include <lib60870/hal_time.h>

IEC104OutstandingCommand::IEC104OutstandingCommand(CS101_ASDU asdu, IMasterConnection connection, int actConTimeout, int actTermTimeout)
{
    m_receivedAsdu = CS101_ASDU_clone(asdu, NULL);

    m_connection = connection;

    m_actConTimeout = actConTimeout;
    m_actTermTimeout = actTermTimeout;

    m_state = 1; /* wait for ACT-CON */

    m_typeId = CS101_ASDU_getTypeID(asdu);
    m_ca = CS101_ASDU_getCA(asdu);
    
    InformationObject io = CS101_ASDU_getElement(asdu, 0);

    if (io) {
        m_ioa = InformationObject_getObjectAddress(io);

        InformationObject_destroy(io);
    }

    m_commandRcvdTime = Hal_getTimeInMs();
    m_nextTimeout = m_commandRcvdTime + m_actConTimeout;
}

IEC104OutstandingCommand::~IEC104OutstandingCommand()
{
    CS101_ASDU_destroy(m_receivedAsdu);
}

bool
IEC104OutstandingCommand::isSentFromConnection(IMasterConnection connection)
{
    return (connection == m_connection);
}

void
IEC104OutstandingCommand::sendActCon(bool negative)
{
    if(IMasterConnection_sendACT_CON(m_connection, m_receivedAsdu, negative) == false) {
        printf("Failed to send ACT-CON\n");
    }

    m_nextTimeout = Hal_getTimeInMs() + m_actTermTimeout;

    m_state = 2; /* wait for ACT-TERM */
}

void
IEC104OutstandingCommand::sendActTerm()
{
    if(IMasterConnection_sendACT_TERM(m_connection, m_receivedAsdu) == false) {
        printf("Failed to send ACT-CON\n");
    }

    m_nextTimeout = 0;

    m_state = 0; /* completed */
}

bool
IEC104OutstandingCommand::isMatching(int typeId, int ca, int ioa)
{
    if (typeId == m_typeId && ca == m_ca && ioa == m_ioa) {
        return true;
    }
    else {
        return false;
    }
}

 bool
 IEC104OutstandingCommand::hasTimedOut(uint64_t currentTime)
 {
    return (currentTime > m_nextTimeout);
 }
