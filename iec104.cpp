/*
 * Fledge IEC 104 north plugin.
 *
 * Copyright (c) 2020, RTE (https://www.rte-france.com)
 * 
 * Released under the Apache 2.0 Licence
 *
 * Author: Akli Rahmoun <akli.rahmoun at rte-france.com>
 */
#include <iec104.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

using namespace std;

static bool running = true;

/**
 * Constructor for the IEC104 Server object
 */
IEC104Server::IEC104Server() {
  m_log = Logger::getLogger();

  /* create a new slave/server instance with default connection parameters and
   * default message queue size */
  m_slave = CS104_Slave_create(10, 10);

  CS104_Slave_setLocalAddress(m_slave, "0.0.0.0");

  /* Set mode to a single redundancy group
   * NOTE: library has to be compiled with CONFIG_CS104_SUPPORT_SERVER_MODE_SINGLE_REDUNDANCY_GROUP enabled (=1)
   */
  CS104_Slave_setServerMode(m_slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);

  /* when you have to tweak the APCI parameters (t0-t3, k, w) you can access them here */
  CS104_APCIParameters apciParams = CS104_Slave_getConnectionParameters(m_slave);

  m_log -> info("APCI parameters:");
  m_log -> info("  t0: %i", apciParams -> t0);
  m_log -> info("  t1: %i", apciParams -> t1);
  m_log -> info("  t2: %i", apciParams -> t2);
  m_log -> info("  t3: %i", apciParams -> t3);
  m_log -> info("  k: %i", apciParams -> k);
  m_log -> info("  w: %i", apciParams -> w);

  /* set the callback handler for the clock synchronization command */
  CS104_Slave_setClockSyncHandler(m_slave, clockSyncHandler, NULL);

  /* set the callback handler for the interrogation command */
  CS104_Slave_setInterrogationHandler(m_slave, interrogationHandler, NULL);

  /* set handler for other message types */
  CS104_Slave_setASDUHandler(m_slave, asduHandler, NULL);

  /* set handler to handle connection requests (optional) */
  CS104_Slave_setConnectionRequestHandler(m_slave, connectionRequestHandler, NULL);

  /* set handler to track connection events (optional) */
  CS104_Slave_setConnectionEventHandler(m_slave, connectionEventHandler, NULL);

  /* uncomment to log messages */
  //CS104_Slave_setRawMessageHandler(m_slave, rawMessageHandler, NULL);

  CS104_Slave_start(m_slave);
}

/**
 * Destructor for the IEC104 Server object
 */
IEC104Server::~IEC104Server() {}

/**
 *
 * @param conf	Fledge configuration category
 */
void IEC104Server::configure(const ConfigCategory * conf) {
  if (conf -> itemExists("name"))
    m_name = conf -> getValue("name");
  else
    m_log -> error("Missing name in configuration");
}

/**
 * Send a block of reading to IEC104 Server
 *
 * @param readings	The readings to send
 * @return 		The number of readings sent
 */
uint32_t IEC104Server::send(const vector < Reading * > & readings) {
  if (CS104_Slave_isRunning(m_slave) == false) {
    m_log -> error("Starting server failed!");
  } else {
    m_log -> info("Server is running!");
  }

  int16_t value;
  int n = 0;

  for (auto reading = readings.cbegin(); reading != readings.cend(); reading++) {
    vector < Datapoint * > & dataPoints = ( * reading) -> getReadingData();
    string assetName = ( * reading) -> getAssetName();

    Datapoint * doh = dataPoints.at(0);
    DatapointValue & hvalue = doh -> getData();
    string hname = doh -> getName();
    vector < Datapoint * > * hdpv = hvalue.getDpVec();

    Datapoint * doi = dataPoints.at(1);
    DatapointValue & ivalue = doi -> getData();
    string iname = doi -> getName();
    vector < Datapoint * > * idpv = ivalue.getDpVec();

    int asdu_ca = hdpv -> at(0) -> getData().toInt();
    auto asdu_cot = static_cast < CS101_CauseOfTransmission > (hdpv -> at(1) -> getData().toInt());
    int asdu_isneg = hdpv -> at(2) -> getData().toInt();
    int asdu_oa = hdpv -> at(3) -> getData().toInt();
    int asdu_istest = hdpv -> at(4) -> getData().toInt();
    auto asdu_type = static_cast < IEC60870_5_TypeID > (hdpv -> at(5) -> getData().toInt());

    int io_ioa = idpv -> at(0) -> getData().toInt();
    auto io_quality = static_cast < QualityDescriptor > (idpv -> at(1) -> getData().toInt());
    auto io_value = idpv -> at(6) -> getData();

    CS101_AppLayerParameters alParams = CS104_Slave_getAppLayerParameters(m_slave);
    CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, asdu_cot, asdu_oa, asdu_ca, asdu_istest, asdu_isneg);

    struct sCP56Time2a CP56TT;
    CP56Time2a_createFromMsTimestamp( & CP56TT, Hal_getTimeInMs());

    switch (asdu_type) {
    case M_ME_NA_1: {
      m_log -> info("	Received asdu type M_ME_NA_1");
      InformationObject io = (InformationObject) MeasuredValueNormalized_create(NULL, io_ioa, io_value.toDouble(), io_quality);
      CS101_ASDU_addInformationObject(newAsdu, io);
      InformationObject_destroy(io);
      CS104_Slave_enqueueASDU(m_slave, newAsdu);
      CS101_ASDU_destroy(newAsdu);
      break;
    }
    case M_ME_NC_1: {
      m_log -> info("	Received asdu type M_ME_NC_1");
      InformationObject io = (InformationObject) MeasuredValueShort_create(NULL, io_ioa, io_value.toDouble(), io_quality);
      CS101_ASDU_addInformationObject(newAsdu, io);
      InformationObject_destroy(io);
      CS104_Slave_enqueueASDU(m_slave, newAsdu);
      CS101_ASDU_destroy(newAsdu);
      break;
    }
    case M_DP_TB_1: {
      m_log -> info("	Received asdu type M_DP_TB_1");
      InformationObject io = (InformationObject) DoublePointWithCP56Time2a_create(NULL, io_ioa, static_cast < DoublePointValue > (io_value.toInt()), io_quality, &CP56TT);
      CS101_ASDU_addInformationObject(newAsdu, io);
      InformationObject_destroy(io);
      CS104_Slave_enqueueASDU(m_slave, newAsdu);
      CS101_ASDU_destroy(newAsdu);
      break;
    }
    case M_ME_NB_1: {
      m_log -> info("	Received asdu type M_ME_NB_1");
      InformationObject io = (InformationObject) MeasuredValueScaled_create(NULL, io_ioa, io_value.toInt(), io_quality);
      CS101_ASDU_addInformationObject(newAsdu, io);
      InformationObject_destroy(io);
      CS104_Slave_enqueueASDU(m_slave, newAsdu);
      CS101_ASDU_destroy(newAsdu);
    }
    case M_ST_TB_1: {
      m_log -> info("	Received asdu type M_ST_TB_1");
      InformationObject io = (InformationObject) StepPositionWithCP56Time2a_create(NULL, io_ioa, io_value.toInt(), false, io_quality, &CP56TT);
      CS101_ASDU_addInformationObject(newAsdu, io);
      InformationObject_destroy(io);
      CS104_Slave_enqueueASDU(m_slave, newAsdu);
      CS101_ASDU_destroy(newAsdu);
    }
    case M_SP_TB_1: {
      m_log -> info("	Received asdu type M_SP_TB_1");
      InformationObject io = (InformationObject) SinglePointWithCP56Time2a_create(NULL, io_ioa, io_value.toInt(), io_quality, &CP56TT);
      CS101_ASDU_addInformationObject(newAsdu, io);
      InformationObject_destroy(io);
      CS104_Slave_enqueueASDU(m_slave, newAsdu);
      CS101_ASDU_destroy(newAsdu);
    }
    default: {
      m_log -> warn("%s is of unknown or not handled ASDU type %i", assetName.c_str(), asdu_type);
      return false;
    }
    }
    n++;
  }
  return n;
}

/**
 * Print time in human readable format
 *
 * @param time CP56Time2a time format
 */
void
IEC104Server::printCP56Time2a(CP56Time2a time) {
  Logger::getLogger() -> info("%02i:%02i:%02i %02i/%02i/%04i", CP56Time2a_getHour(time),
    CP56Time2a_getMinute(time),
    CP56Time2a_getSecond(time),
    CP56Time2a_getDayOfMonth(time),
    CP56Time2a_getMonth(time),
    CP56Time2a_getYear(time) + 2000);
}

/**
 * Callback handler to log sent or received messages (optional)
 *
 * @param parameter
 * @param connection	connection object
 * @param msg	        message
 * @param msgSize	    message size
 * @param sent	        boolean
 */
void
IEC104Server::rawMessageHandler(void * parameter, IMasterConnection connection, uint8_t * msg, int msgSize, bool sent) {
  if (sent)
    Logger::getLogger() -> info("SEND: ");
  else
    Logger::getLogger() -> info("RCVD: ");

  int i;
  for (i = 0; i < msgSize; i++) {
    Logger::getLogger() -> info("%02x ", msg[i]);
  }
}

/**
 * Callback handler for clock synchronization
 *
 * @param parameter
 * @param connection	connection object
 * @param asdu	        asdu
 * @param newTime	    new time
 * @return 		boolean
 */
bool
IEC104Server::clockSyncHandler(void * parameter, IMasterConnection connection, CS101_ASDU asdu, CP56Time2a newTime) {
  Logger::getLogger() -> info("Process time sync command with time ");
  printCP56Time2a(newTime);

  uint64_t newSystemTimeInMs = CP56Time2a_toMsTimestamp(newTime);

  /* Set time for ACT_CON message */
  CP56Time2a_setFromMsTimestamp(newTime, Hal_getTimeInMs());

  /* update system time here */

  return true;
}

/**
 * Callback handler for station interrogation
 *
 * @param parameter
 * @param connection	connection object
 * @param asdu	        asdu
 * @param qoi	        qoi
 * @return 		boolean
 */
bool
IEC104Server::interrogationHandler(void * parameter, IMasterConnection connection, CS101_ASDU asdu, uint8_t qoi) {
  Logger::getLogger() -> info("Received interrogation for group %i", qoi);

  if (qoi == 20) {
    /* only handle station interrogation */

    CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);

    IMasterConnection_sendACT_CON(connection, asdu, false);

    /* The CS101 specification only allows information objects without timestamp in GI responses */

    CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
      0, 1, false, false);

    InformationObject io = (InformationObject) MeasuredValueScaled_create(NULL, 100, -1, IEC60870_QUALITY_GOOD);

    CS101_ASDU_addInformationObject(newAsdu, io);

    CS101_ASDU_addInformationObject(newAsdu, (InformationObject) MeasuredValueScaled_create((MeasuredValueScaled) io, 101, 23, IEC60870_QUALITY_GOOD));

    CS101_ASDU_addInformationObject(newAsdu, (InformationObject) MeasuredValueScaled_create((MeasuredValueScaled) io, 102, 2300, IEC60870_QUALITY_GOOD));

    InformationObject_destroy(io);

    IMasterConnection_sendASDU(connection, newAsdu);

    CS101_ASDU_destroy(newAsdu);

    newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
      0, 1, false, false);

    io = (InformationObject) SinglePointInformation_create(NULL, 104, true, IEC60870_QUALITY_GOOD);

    CS101_ASDU_addInformationObject(newAsdu, io);

    CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 105, false, IEC60870_QUALITY_GOOD));

    InformationObject_destroy(io);

    IMasterConnection_sendASDU(connection, newAsdu);

    CS101_ASDU_destroy(newAsdu);

    newAsdu = CS101_ASDU_create(alParams, true, CS101_COT_INTERROGATED_BY_STATION,
      0, 1, false, false);

    CS101_ASDU_addInformationObject(newAsdu, io = (InformationObject) SinglePointInformation_create(NULL, 300, true, IEC60870_QUALITY_GOOD));
    CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 301, false, IEC60870_QUALITY_GOOD));
    CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 302, true, IEC60870_QUALITY_GOOD));
    CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 303, false, IEC60870_QUALITY_GOOD));
    CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 304, true, IEC60870_QUALITY_GOOD));
    CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 305, false, IEC60870_QUALITY_GOOD));
    CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 306, true, IEC60870_QUALITY_GOOD));
    CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 307, false, IEC60870_QUALITY_GOOD));

    InformationObject_destroy(io);

    IMasterConnection_sendASDU(connection, newAsdu);

    CS101_ASDU_destroy(newAsdu);

    newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION,
      0, 1, false, false);

    io = (InformationObject) BitString32_create(NULL, 500, 0xaaaa);

    CS101_ASDU_addInformationObject(newAsdu, io);

    InformationObject_destroy(io);

    IMasterConnection_sendASDU(connection, newAsdu);

    CS101_ASDU_destroy(newAsdu);

    IMasterConnection_sendACT_TERM(connection, asdu);
  } else {
    IMasterConnection_sendACT_CON(connection, asdu, true);
  }

  return true;
}

/**
 * Callback handler for ASDU handling
 *
 * @param parameter
 * @param connection	connection object
 * @param asdu	        asdu
 * @return 		boolean
 */
bool
IEC104Server::asduHandler(void * parameter, IMasterConnection connection, CS101_ASDU asdu) {
  if (CS101_ASDU_getTypeID(asdu) == C_SC_NA_1) {
    Logger::getLogger() -> info("received single command");

    if (CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION) {
      InformationObject io = CS101_ASDU_getElement(asdu, 0);

      if (InformationObject_getObjectAddress(io) == 5000) {
        SingleCommand sc = (SingleCommand) io;

        Logger::getLogger() -> info("IOA: %i switch to %i", InformationObject_getObjectAddress(io),
          SingleCommand_getState(sc));

        CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
      } else
        CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);

      InformationObject_destroy(io);
    } else
      CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT);

    IMasterConnection_sendASDU(connection, asdu);

    return true;
  }

  return false;
}

/**
 * Callback handler for connection request handling
 *
 * @param parameter
 * @param ipAddress	    incoming connection request IP address
 * @return 		boolean
 */
bool
IEC104Server::connectionRequestHandler(void * parameter,
  const char * ipAddress) {
  Logger::getLogger() -> info("New connection request from %s", ipAddress);

  #if 0
  if (strcmp(ipAddress, "127.0.0.1") == 0) {
    Logger::getLogger() -> info("Accept connection");
    return true;
  } else {
    Logger::getLogger() -> warn("Deny connection");
    return false;
  }
  #else
  return true;
  #endif
}

/**
 * Callback handler for connection event handling
 *
 * @param parameter
 * @param connection	connection object
 * @param event         peer connection event object
 */
void
IEC104Server::connectionEventHandler(void * parameter, IMasterConnection con, CS104_PeerConnectionEvent event) {
  if (event == CS104_CON_EVENT_CONNECTION_OPENED) {
    Logger::getLogger() -> info("Connection opened (%p)", con);
  } else if (event == CS104_CON_EVENT_CONNECTION_CLOSED) {
    Logger::getLogger() -> info("Connection closed (%p)", con);
  } else if (event == CS104_CON_EVENT_ACTIVATED) {
    Logger::getLogger() -> info("Connection activated (%p)", con);
  } else if (event == CS104_CON_EVENT_DEACTIVATED) {
    Logger::getLogger() -> info("Connection deactivated (%p)", con);
  }
}

/**
 * Stop the IEC104 Server
 */
void IEC104Server::stop() {
  if (m_slave) {
    CS104_Slave_stop(m_slave);
    CS104_Slave_destroy(m_slave);
  }
}