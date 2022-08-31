#include <map>
#include "iec104_datapoint.hpp"

// Map of all handled ASDU types by the plugin
static std::map<std::string, int> mapAsduTypeId = {
    {"M_ME_NB_1", M_ME_NB_1},
    {"M_SP_NA_1", M_SP_NA_1},
    {"M_SP_TB_1", M_SP_TB_1},
    {"M_DP_NA_1", M_DP_NA_1},
    {"M_DP_TB_1", M_DP_TB_1},
    {"M_ST_NA_1", M_ST_NA_1},
    {"M_ST_TB_1", M_ST_TB_1},
    {"M_ME_NA_1", M_ME_NA_1},
    {"M_ME_TD_1", M_ME_TD_1},
    {"M_ME_TE_1", M_ME_TE_1},
    {"M_ME_NC_1", M_ME_NC_1},
    {"M_ME_TF_1", M_ME_TF_1},
    {"C_SC_NA_1", C_SC_NA_1},
    {"C_SC_TA_1", C_SC_TA_1},
    {"C_DC_NA_1", C_DC_NA_1},
    {"C_DC_TA_1", C_DC_TA_1},
    {"C_RC_NA_1", C_RC_NA_1},
    {"C_RC_TA_1", C_RC_TA_1},
    {"C_SE_NA_1", C_SE_NA_1},
    {"C_SE_TA_1", C_SE_TA_1},
    {"C_SE_NB_1", C_SE_NB_1},
    {"C_SE_TB_1", C_SE_TB_1},
    {"C_SE_NC_1", C_SE_NC_1},
    {"C_SE_TC_1", C_SE_TC_1}
};

static std::map<int, std::string> mapAsduTypeIdStr = {
    {M_ME_NB_1, "M_ME_NB_1"},
    {M_SP_NA_1, "M_SP_NA_1"},
    {M_SP_TB_1, "M_SP_TB_1"},
    {M_DP_NA_1, "M_DP_NA_1"},
    {M_DP_TB_1, "M_DP_TB_1"},
    {M_ST_NA_1, "M_ST_NA_1"},
    {M_ST_TB_1, "M_ST_TB_1"},
    {M_ME_NA_1, "M_ME_NA_1"},
    {M_ME_TD_1, "M_ME_TD_1"},
    {M_ME_TE_1, "M_ME_TE_1"},
    {M_ME_NC_1, "M_ME_NC_1"},
    {M_ME_TF_1, "M_ME_TF_1"},
    {C_SC_TA_1, "C_SC_TA_1"},
    {C_SC_NA_1, "C_SC_NA_1"},
    {C_DC_TA_1, "C_DC_TA_1"},
    {C_DC_NA_1, "C_DC_NA_1"},
    {C_RC_TA_1, "C_RC_TA_1"},
    {C_RC_NA_1, "C_RC_NA_1"},
    {C_SE_TA_1, "C_SE_TA_1"},
    {C_SE_NA_1, "C_SE_NA_1"},
    {C_SE_TB_1, "C_SE_TB_1"},
    {C_SE_NB_1, "C_SE_NB_1"},
    {C_SE_TC_1, "C_SE_TC_1"},
    {C_SE_NC_1, "C_SE_NC_1"}
};

bool
IEC104DataPoint::isSupportedCommandType(int typeId)
{
    switch (typeId) {
        case C_SC_NA_1:
        case C_SC_TA_1:
        case C_DC_NA_1:
        case C_DC_TA_1:
        case C_RC_NA_1:
        case C_RC_TA_1:
        case C_SE_NA_1:
        case C_SE_TA_1:
        case C_SE_NB_1:
        case C_SE_TB_1:
        case C_SE_NC_1:
        case C_SE_TC_1:
            return true;

        default:
            return false;
    }
}

bool
IEC104DataPoint::isCommandWithTimestamp(int typeId)
{
    switch (typeId) {
        case C_SC_TA_1:
        case C_DC_TA_1:
        case C_RC_TA_1:
        case C_SE_TA_1:
        case C_SE_TB_1:
        case C_SE_TC_1:
            return true;

        default:
            return false;
    }
}

bool
IEC104DataPoint::isSupportedMonitoringType(int typeId)
{
    switch (typeId) {
        case M_SP_NA_1:
        case M_SP_TA_1:
        case M_SP_TB_1:
        case M_DP_NA_1:
        case M_DP_TA_1:
        case M_DP_TB_1:
        case M_ST_NA_1:
        case M_ST_TA_1:
        case M_ST_TB_1:
        case M_ME_NA_1:
        case M_ME_TA_1:
        case M_ME_TD_1:
        case M_ME_NB_1:
        case M_ME_TB_1:
        case M_ME_TE_1:
        case M_ME_NC_1:
        case M_ME_TC_1:
        case M_ME_TF_1:
            return true;

        default:
            return false;
    }
}

int
IEC104DataPoint::typeIdToDataType(int typeId)
{
    int dataType = 0;

    switch (typeId) {
        case M_SP_NA_1:
        case M_SP_TA_1:
        case M_SP_TB_1:
        case C_SC_NA_1:
        case C_SC_TA_1:
            dataType = IEC60870_TYPE_SP;
            break;

        case M_DP_NA_1:
        case M_DP_TA_1:
        case M_DP_TB_1:
        case C_DC_NA_1:
        case C_DC_TA_1:
            dataType = IEC60870_TYPE_DP;
            break;

        case M_ST_NA_1:
        case M_ST_TA_1:
        case M_ST_TB_1:
        case C_RC_NA_1:
        case C_RC_TA_1:
            dataType = IEC60870_TYPE_STEP_POS;
            break;

        case M_ME_NA_1:
        case M_ME_TA_1:
        case M_ME_TD_1:
        case C_SE_NA_1:
        case C_SE_TA_1:
            dataType = IEC60870_TYPE_NORMALIZED;
            break;

        case M_ME_NB_1:
        case M_ME_TB_1:
        case M_ME_TE_1:
        case C_SE_NB_1:
        case C_SE_TB_1:
            dataType = IEC60870_TYPE_SCALED;
            break;

        case M_ME_NC_1:
        case M_ME_TC_1:
        case M_ME_TF_1:
        case C_SE_NC_1:
        case C_SE_TC_1:
            dataType = IEC60870_TYPE_SHORT;
            break;

        default:
            break;
    }

    return dataType;
}

int IEC104DataPoint::getTypeIdFromString(std::string typeIdStr)
{
    return mapAsduTypeId[typeIdStr];
}

std::string IEC104DataPoint::getStringFromTypeID(int typeId)
{
    return mapAsduTypeIdStr[typeId];
}

bool IEC104DataPoint::isMonitoringType()
{
    if (m_isCommand)
        return false;
    else
        return true;
}

bool IEC104DataPoint::isCommand()
{
    return m_isCommand;
}

bool IEC104DataPoint::isMatchingCommand(int typeId)
{
    if (isCommand()) {
        if (m_type == IEC60870_TYPE_SP) {
            if (typeId == C_SC_NA_1 || typeId == C_SC_TA_1)
                return true;
            else
                return false;
        }
        else if (m_type == IEC60870_TYPE_DP) {
            if (typeId == C_DC_NA_1 || typeId == C_DC_TA_1)
                return true;
            else
                return false;
        }
        else if (m_type == IEC60870_TYPE_STEP_POS) {
            if (typeId == C_RC_NA_1 || typeId == C_RC_TA_1)
                return true;
            else
                return false;
        }
        else if (m_type == IEC60870_TYPE_NORMALIZED) {
            if (typeId == C_SE_NA_1 || typeId == C_SE_TA_1)
                return true;
            else
                return false;
        }
        else if (m_type == IEC60870_TYPE_SCALED) {
            if (typeId == C_SE_NB_1 || typeId == C_SE_TB_1)
                return true;
            else
                return false;
        }
        else if (m_type == IEC60870_TYPE_SHORT) {
            if (typeId == C_SE_NC_1 || typeId == C_SE_TC_1)
                return true;
            else
                return false;
        }
    }
    
    return false;
}

IEC104DataPoint::IEC104DataPoint(std::string label, int ca, int ioa, int type, bool isCommand)
{
    m_ca = ca;
    m_ioa = ioa;
    m_type = type;
    m_isCommand = isCommand;
    m_label = label;

    //TODO set intial value and quality to invalid

    switch (type) {
        case IEC60870_TYPE_SP:
            m_value.sp.value = 0;
            m_value.sp.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;
            
            break;

        case IEC60870_TYPE_DP:
            m_value.dp.value = 0;
            m_value.dp.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;
            
            break;

        case IEC60870_TYPE_STEP_POS:
            m_value.stepPos.posValue = 0;
            m_value.stepPos.transient = 0;
            m_value.stepPos.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;
            
            break;

        case IEC60870_TYPE_NORMALIZED:
            m_value.mv_normalized.value = 0;
            m_value.mv_normalized.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;

            break;

        case IEC60870_TYPE_SCALED:
            m_value.mv_scaled.value = 0;
            m_value.mv_scaled.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;

            break;

        case IEC60870_TYPE_SHORT:
            m_value.mv_short.value = 0;
            m_value.mv_short.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;

            break;
    } 
}
