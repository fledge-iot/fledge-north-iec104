#include "iec104.h"

#include <lib60870/hal_time.h>

IEC104OutstandingCommand::IEC104OutstandingCommand(CS101_ASDU asdu, IMasterConnection connection, int cmdExecTimeout, bool isSelect)
{
    m_receivedAsdu = CS101_ASDU_clone(asdu, NULL);

    m_connection = connection;

    m_cmdExecTimeout = cmdExecTimeout;

    m_state = 1; /* wait for ACT-CON */

    m_typeId = CS101_ASDU_getTypeID(asdu);
    m_ca = CS101_ASDU_getCA(asdu);

    m_isSelect = isSelect;
    
    InformationObject io = CS101_ASDU_getElement(asdu, 0);

    if (io) {
        m_ioa = InformationObject_getObjectAddress(io);

        InformationObject_destroy(io);
    }

    m_commandRcvdTime = Hal_getTimeInMs();
    m_nextTimeout = m_commandRcvdTime + (m_cmdExecTimeout * 1000);
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

    if ((negative == false) && (m_isSelect == false)) {
        m_state = 2; /* wait for ACT-TERM */
    }
    else {
        m_nextTimeout = 0;

        m_state = 0; /* completed */
    }
}

void
IEC104OutstandingCommand::sendActTerm(bool negative)
{
    CS101_ASDU_setNegative(m_receivedAsdu, negative);

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
IEC104OutstandingCommand::isSelect()
{
    return m_isSelect;
}

bool
IEC104OutstandingCommand::hasTimedOut(uint64_t currentTime)
{
   return (currentTime > m_nextTimeout);
}
