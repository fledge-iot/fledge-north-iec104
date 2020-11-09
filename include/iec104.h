#ifndef _IEC104SERVER_H
#define _IEC104SERVER_H

/*
 * Fledge IEC 104 north plugin.
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Akli Rahmoun
 */

#include <reading.h>
#include <config_category.h>
#include <logger.h>
#include <string>
#include "cs104_slave.h"
#include "cs101_information_objects.h"
#include "hal_thread.h"
#include "hal_time.h"

class IEC104Server {
	public:
		IEC104Server();
		~IEC104Server();
		void		configure(const ConfigCategory *conf);
		uint32_t	send(const std::vector<Reading *>& readings);
		void		stop();
	private:
        static void        printCP56Time2a(CP56Time2a time);
        static void        rawMessageHandler(void* parameter, IMasterConnection conneciton, uint8_t* msg, int msgSize, bool sent);
        static bool        clockSyncHandler (void* parameter, IMasterConnection connection, CS101_ASDU asdu, CP56Time2a newTime);
        static bool        interrogationHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, uint8_t qoi);
		static bool        asduHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu);
        static bool        connectionRequestHandler(void* parameter, const char* ipAddress);
        static void        connectionEventHandler(void* parameter, IMasterConnection con, CS104_PeerConnectionEvent event);
		CS104_Slave				 m_slave{};
		CS101_AppLayerParameters alParams;
		std::string	 	 		 m_name;
		Logger					 *m_log;
};

#endif
