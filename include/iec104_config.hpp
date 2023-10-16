#ifndef IEC104_CONFIG_H
#define IEC104_CONFIG_H

#include <map>
#include <vector>

#include <lib60870/cs104_slave.h>

class IEC104DataPoint;

class IEC104Config
{
public:
    IEC104Config();
    IEC104Config(const std::string& protocolConfig, const std::string& exchangeConfig);
    ~IEC104Config();

    void importProtocolConfig(const std::string& protocolConfig);
    void importExchangeConfig(const std::string& exchangeConfig);
    void importTlsConfig(const std::string& tlsConfig);

    std::map<int, std::map<int, IEC104DataPoint*>>* getExchangeDefinitions() {return m_exchangeDefinitions;};

    std::vector<CS104_RedundancyGroup> getRedGroups() {return m_configuredRedundancyGroups;};

    int TcpPort();
    bool bindOnIp() {return m_bindOnIp;};
    int K() {return m_k;};
    int W() {return m_w;};
    int T0() {return m_t0;};
    int T1() {return m_t1;};
    int T2() {return m_t2;};
    int T3() {return m_t3;};
    int UseTLS() {return m_useTls;};
    const char* GetLocalIP() {return m_ip.c_str();};

    int CaSize() {return m_caSize;};
    int IOASize() {return m_ioaSize;};
    int AsduSize() {return m_asduSize;};

    int AsduQueueSize() {return m_asduQueueSize;};

    bool TimeSync() {return m_timeSync;};

    bool IsOriginatorAllowed(int oa);

    bool AllowCmdWithTime();
    bool AllowCmdWithoutTime();

    int CmdRecvTimeout() {return m_cmdRecvTimeout;};
    int CmdExecTimeout() {return m_cmdExecTimeout;};

    std::string& CmdDest() {return m_cmdDest;};

    std::string& GetPrivateKey() {return m_privateKey;};
    std::string& GetOwnCertificate() {return m_ownCertificate;};
    std::vector<std::string>& GetRemoteCertificates() {return m_remoteCertificates;};
    std::vector<std::string>& GetCaCertificates() {return m_caCertificates;};

    enum class Mode
    {
        CONNECT_ALWAYS,
        CONNECT_IF_SOUTH_CONNX_STARTED
    };

    Mode GetMode() {return m_mode;};

    enum class ConnectionStatus
    {
        STARTED,
        NOT_CONNECTED
    };

    enum class GiStatus
    {
        IDLE,
        STARTED,
        IN_PROGRESS,
        FAILED,
        FINISHED
    };

    class SouthPluginMonitor {
        
    public:
        SouthPluginMonitor(std::string& assetName);

        std::string& GetAssetName() {return m_assetName;};

        ConnectionStatus GetConnxStatus() {return m_connxStatus;};
        GiStatus GetGiStatus() {return m_giStatus;};

        void SetConnxStatus(ConnectionStatus status) {m_connxStatus = status;};
        void SetGiStatus(GiStatus status) {m_giStatus = status;};

    private:

        std::string m_assetName;
        ConnectionStatus m_connxStatus;
        GiStatus m_giStatus;
    };

    std::vector<SouthPluginMonitor*> GetMonitoredSouthPlugins() {return m_monitoredSouthPlugins;};

private:

    static bool isValidIPAddress(const std::string& addrStr);

    void deleteExchangeDefinitions();

    Mode m_mode = Mode::CONNECT_ALWAYS;
    
    bool m_protocolConfigComplete;
    bool m_exchangeConfigComplete;

    bool m_useTls = false;
    int m_tcpPort = -1; /* use default port */
    bool m_bindOnIp = false;
    int m_k = 12;
    int m_w = 8;
    int m_t0 = 30;
    int m_t1 = 15;
    int m_t2 = 10;
    int m_t3 = 20;

    int m_caSize = 2;
    int m_ioaSize = 3;
    int m_asduSize = 0;

    int m_asduQueueSize = 100;

    bool m_timeSync = false;
    bool m_filterOriginators = false;

    int m_allowedCommands = 1; /* 0 - only without timestamp, 1 - only with timestamp, 2 - both */

    int m_cmdRecvTimeout = 0;
    int m_cmdExecTimeout = 20;

    std::string m_ip;

    std::string m_cmdDest = "";

    std::vector<CS104_RedundancyGroup> m_configuredRedundancyGroups;

    std::vector<SouthPluginMonitor*> m_monitoredSouthPlugins;

    std::map<int, std::map<int, IEC104DataPoint*>>* m_exchangeDefinitions = nullptr;
    std::map<int, int> m_allowedOriginators;

    std::string m_privateKey;
    std::string m_ownCertificate;
    std::vector<std::string> m_remoteCertificates;
    std::vector<std::string> m_caCertificates;
};

#endif /* IEC104_CONFIG_H */