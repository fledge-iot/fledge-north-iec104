#ifndef IEC104_DATAPOINT_H
#define IEC104_DATAPOINT_H

#include <string>

#include "lib60870/cs101_information_objects.h"

#define IEC60870_TYPE_SP 1
#define IEC60870_TYPE_DP 2
#define IEC60870_TYPE_STEP_POS 3
#define IEC60870_TYPE_NORMALIZED 4
#define IEC60870_TYPE_SCALED 5
#define IEC60870_TYPE_SHORT 6

class IEC104DataPoint
{
public:

    IEC104DataPoint(std::string label, int ca, int ioa, int type, bool isCommand);
    ~IEC104DataPoint() {};

    static bool isSupportedCommandType(int typeId);
    static bool isCommandWithTimestamp(int typeId);
    static bool isSupportedMonitoringType(int typeId);
    static int typeIdToDataType(int typeId);
    static int getTypeIdFromString(std::string typeIdStr);
    static std::string getStringFromTypeID(int typeId);

    bool isMonitoringType();

    bool isCommand();

    bool isMessageTypeMatching(int msgTypeId);

    bool isMatchingCommand(int typeId);

    int m_ca;
    int m_ioa;
    int m_type;
    bool m_isCommand;
    std::string m_label;

    int terminationTimeout; /* termination timeout for commands in ms */

    union {
        struct {
            unsigned int value : 1;
            uint8_t quality;
        } sp; /* IEC60870_TYPE_SP */

        struct {
            unsigned int value : 2;
            uint8_t quality;
        } dp; /* IEC60870_TYPE_DP */

        struct {
            int posValue : 7; /* I7[1..7]<-64..+63> */
            unsigned int transient : 1;
            uint8_t quality;
        } stepPos; /* IEC60870_TYPE_STEP_POS */

        struct {
            float value;
            uint8_t quality;
        } mv_normalized; /* IEC60870_TYPE_NORMALIZED */

        struct {
            int16_t value;
            uint8_t quality;
        } mv_scaled; /* IEC60870_TYPE_SCALED */

        struct {
            float value;
            uint8_t quality;
        } mv_short; /* IEC60870_TYPE_SHORT */

        uint32_t bitstring; /* IEC60870_TYPE_BITSTRING */

        struct {
            int32_t value;
            struct {
                unsigned int seq : 5;
                unsigned int cy : 1;
                unsigned int ca : 1;
                unsigned int invalid : 1;
            } quality;
        } counter; /* IEC60870_TYPE_COUNTER */

        struct {
            uint8_t sep;
            uint16_t elapsed;
        } single_event; /* IEC60870_TYPE_SINGLE_EVENT */

        struct {
            uint8_t spe;
            uint8_t quality;
            uint16_t elapsed;
        } start_events; /* IEC60870_TYPE_PACKED_START_EVENTS */

        struct {
            uint8_t oci;
            uint8_t quality;
            uint16_t elapsed;
        } out_info; /* IEC60870_TYPE_PACKED_OUTPUT_INFO */

        struct {
            union {
                float f;
                int16_t i;
            } val;
            unsigned int kind : 6;
            unsigned int active : 1;
            unsigned int refIoa : 24;
        } param_mv; /* IEC60870_TYPE_PARAM_MV_... */
    } m_value;

    struct sCP56Time2a m_ts;
};

#endif /* IEC104_DATAPOINT_H */