#include <map>

#include "iec104_datapoint.hpp"

// Map of all existing ASDU types
static std::map<std::string, int> mapAsduTypeId = {
    {"M_SP_TA_1", M_SP_TA_1},
    {"M_SP_NA_1", M_SP_NA_1},
    {"M_DP_NA_1", M_DP_NA_1},
    {"M_DP_TA_1", M_DP_TA_1},
    {"M_ST_NA_1", M_ST_NA_1},
    {"M_ST_TA_1", M_ST_TA_1},
    {"M_BO_NA_1", M_BO_NA_1},
    {"M_BO_TA_1", M_BO_TA_1},
    {"M_ME_NA_1", M_ME_NA_1},
    {"M_ME_TA_1", M_ME_TA_1},
    {"M_ME_NB_1", M_ME_NB_1},
    {"M_ME_TB_1", M_ME_TB_1},
    {"M_ME_NC_1", M_ME_NC_1},
    {"M_ME_TC_1", M_ME_TC_1},
    {"M_IT_NA_1", M_IT_NA_1},
    {"M_IT_TA_1", M_IT_TA_1},
    {"M_EP_TA_1", M_EP_TA_1},
    {"M_EP_TB_1", M_EP_TB_1},
    {"M_EP_TC_1", M_EP_TC_1},
    {"M_PS_NA_1", M_PS_NA_1},
    {"M_ME_ND_1", M_ME_ND_1},
    {"M_SP_TB_1", M_SP_TB_1},
    {"M_DP_TB_1", M_DP_TB_1},
    {"M_ST_TB_1", M_ST_TB_1},
    {"M_BO_TB_1", M_BO_TB_1},
    {"M_ME_TD_1", M_ME_TD_1},
    {"M_ME_TE_1", M_ME_TE_1},
    {"M_ME_TF_1", M_ME_TF_1},
    {"M_IT_TB_1", M_IT_TB_1},
    {"M_EP_TD_1", M_EP_TD_1},
    {"M_EP_TE_1", M_EP_TE_1},
    {"M_EP_TF_1", M_EP_TF_1},
    {"S_IT_TC_1", S_IT_TC_1},
    {"C_SC_NA_1", C_SC_NA_1},
    {"C_DC_NA_1", C_DC_NA_1},
    {"C_RC_NA_1", C_RC_NA_1},
    {"C_SE_NA_1", C_SE_NA_1},
    {"C_SE_NB_1", C_SE_NB_1},
    {"C_SE_NC_1", C_SE_NC_1},
    {"C_BO_NA_1", C_BO_NA_1},
    {"C_SC_TA_1", C_SC_TA_1},
    {"C_DC_TA_1", C_DC_TA_1},
    {"C_RC_TA_1", C_RC_TA_1},
    {"C_SE_TA_1", C_SE_TA_1},
    {"C_SE_TB_1", C_SE_TB_1},
    {"C_SE_TC_1", C_SE_TC_1},
    {"C_BO_TA_1", C_BO_TA_1},
    {"M_EI_NA_1", M_EI_NA_1},
    {"S_CH_NA_1", S_CH_NA_1},
    {"S_RP_NA_1", S_RP_NA_1},
    {"S_AR_NA_1", S_AR_NA_1},
    {"S_KR_NA_1", S_KR_NA_1},
    {"S_KS_NA_1", S_KS_NA_1},
    {"S_KC_NA_1", S_KC_NA_1},
    {"S_ER_NA_1", S_ER_NA_1},
    {"S_US_NA_1", S_US_NA_1},
    {"S_UQ_NA_1", S_UQ_NA_1},
    {"S_UR_NA_1", S_UR_NA_1},
    {"S_UK_NA_1", S_UK_NA_1},
    {"S_UA_NA_1", S_UA_NA_1},
    {"S_UC_NA_1", S_UC_NA_1},
    {"C_IC_NA_1", C_IC_NA_1},
    {"C_CI_NA_1", C_CI_NA_1},
    {"C_RD_NA_1", C_RD_NA_1},
    {"C_CS_NA_1", C_CS_NA_1},
    {"C_TS_NA_1", C_TS_NA_1},
    {"C_RP_NA_1", C_RP_NA_1},
    {"C_CD_NA_1", C_CD_NA_1},
    {"C_TS_TA_1", C_TS_TA_1},
    {"P_ME_NA_1", P_ME_NA_1},
    {"P_ME_NB_1", P_ME_NB_1},
    {"P_ME_NC_1", P_ME_NC_1},
    {"P_AC_NA_1", P_AC_NA_1},
    {"F_FR_NA_1", F_FR_NA_1},
    {"F_SR_NA_1", F_SR_NA_1},
    {"F_SC_NA_1", F_SC_NA_1},
    {"F_LS_NA_1", F_LS_NA_1},
    {"F_AF_NA_1", F_AF_NA_1},
    {"F_SG_NA_1", F_SG_NA_1},
    {"F_DR_TA_1", F_DR_TA_1},
    {"F_SC_NB_1", F_SC_NB_1}
};

// Map is automatically initialized from mapAsduTypeId at first getStringFromTypeID() call
static std::map<int, std::string> mapAsduTypeIdStr = {};

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
            break; //LCOV_EXCL_LINE 

        case M_DP_NA_1:
        case M_DP_TA_1:
        case M_DP_TB_1:
        case C_DC_NA_1:
        case C_DC_TA_1:
            dataType = IEC60870_TYPE_DP;
            break; //LCOV_EXCL_LINE

        case M_ST_NA_1:
        case M_ST_TA_1:
        case M_ST_TB_1:
        case C_RC_NA_1:
        case C_RC_TA_1:
            dataType = IEC60870_TYPE_STEP_POS;
            break; //LCOV_EXCL_LINE

        case M_ME_NA_1:
        case M_ME_TA_1:
        case M_ME_TD_1:
        case C_SE_NA_1:
        case C_SE_TA_1:
            dataType = IEC60870_TYPE_NORMALIZED;
            break; //LCOV_EXCL_LINE

        case M_ME_NB_1:
        case M_ME_TB_1:
        case M_ME_TE_1:
        case C_SE_NB_1:
        case C_SE_TB_1:
            dataType = IEC60870_TYPE_SCALED;
            break; //LCOV_EXCL_LINE

        case M_ME_NC_1:
        case M_ME_TC_1:
        case M_ME_TF_1:
        case C_SE_NC_1:
        case C_SE_TC_1:
            dataType = IEC60870_TYPE_SHORT;
            break; //LCOV_EXCL_LINE

        default:
            break; //LCOV_EXCL_LINE
    }

    return dataType;
}

int
IEC104DataPoint::getTypeIdFromString(std::string typeIdStr)
{
    return mapAsduTypeId[typeIdStr];
}

std::string
IEC104DataPoint::getStringFromTypeID(int typeId)
{
    // Build reverse mapping if not yet initialized
    if (mapAsduTypeIdStr.empty()) {
        for(const auto& kvp : mapAsduTypeId) {
            mapAsduTypeIdStr[kvp.second]=kvp.first;
        }
    }
    
    return mapAsduTypeIdStr[typeId];
}

bool
IEC104DataPoint::isMonitoringType()
{
    if (m_isCommand)
        return false;
    else
        return true;
}

bool
IEC104DataPoint::isCommand()
{
    return m_isCommand;
}
 
bool
IEC104DataPoint::isMessageTypeMatching(int expectedType)
{
    bool isMatching = false;

        switch (expectedType) {

        case M_SP_NA_1:
        case M_SP_TB_1:
            if (m_type == IEC60870_TYPE_SP) {
                isMatching = true;
            }

            break; //LCOV_EXCL_LINE

        case M_DP_NA_1:
        case M_DP_TB_1:
            if (m_type == IEC60870_TYPE_DP) {
                isMatching = true;
            }

            break; //LCOV_EXCL_LINE

        case M_ME_NA_1:
        case M_ME_TD_1:
            if (m_type == IEC60870_TYPE_NORMALIZED) {
                isMatching = true;
            }

            break; //LCOV_EXCL_LINE

        case M_ME_NB_1:
        case M_ME_TE_1:
            if (m_type == IEC60870_TYPE_SCALED) {
                isMatching = true;
            }

            break; //LCOV_EXCL_LINE

        case M_ME_NC_1:
        case M_ME_TF_1:
            if (m_type == IEC60870_TYPE_SHORT) {
                isMatching = true;
            }

            break; //LCOV_EXCL_LINE

        case M_ST_NA_1:
        case M_ST_TB_1:
            if (m_type == IEC60870_TYPE_STEP_POS) {
                isMatching = true;
            }

            break; //LCOV_EXCL_LINE

        default:
            //Type not supported
            break; //LCOV_EXCL_LINE
    }

    return isMatching;
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



IEC104DataPoint::IEC104DataPoint(std::string label, int ca, int ioa, int type, bool isCommand, int gi_groups)
{
    m_ca = ca;
    m_ioa = ioa;
    m_type = type;
    m_isCommand = isCommand;
    m_label = label;
    m_gi_groups = gi_groups;
    m_value = {};

    //TODO set intial value and quality to invalid

    switch (type) {
        case IEC60870_TYPE_SP:
            m_value.sp.value = 0;
            m_value.sp.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;
            
            break; //LCOV_EXCL_LINE

        case IEC60870_TYPE_DP:
            m_value.dp.value = 0;
            m_value.dp.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;
            
            break; //LCOV_EXCL_LINE

        case IEC60870_TYPE_STEP_POS:
            m_value.stepPos.posValue = 0;
            m_value.stepPos.transient = 0;
            m_value.stepPos.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;
            
            break; //LCOV_EXCL_LINE

        case IEC60870_TYPE_NORMALIZED:
            m_value.mv_normalized.value = 0;
            m_value.mv_normalized.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;

            break; //LCOV_EXCL_LINE

        case IEC60870_TYPE_SCALED:
            m_value.mv_scaled.value = 0;
            m_value.mv_scaled.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;

            break; //LCOV_EXCL_LINE

        case IEC60870_TYPE_SHORT:
            m_value.mv_short.value = 0;
            m_value.mv_short.quality = IEC60870_QUALITY_INVALID | IEC60870_QUALITY_NON_TOPICAL;

            break; //LCOV_EXCL_LINE
    } 
}
