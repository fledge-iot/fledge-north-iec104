#include <gtest/gtest.h>
#include <iec104.h>

#include <memory>
#include <utility>

#include "cs104_connection.h"
using namespace std;

static string protocol_stack = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":2404,
                "tls":false,
                "k_value":12,
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ]
            }
        }
    });

static string protocol_stack_2 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":19998,
                "tls":true,
                "k_value":12,
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ]
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1"
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });

static string protocol_stack_3 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":{},
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":19998,
                "tls":true,
                "k_value":12,
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ]
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1"
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });

static string broken_protocol_stack_1 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
            },
            "application_layer" : {

            }
        }
    });


static string broken_protocol_stack_2 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"01.0.0.0",
                "port":"",
                "tls":true,
                "k_value":"",
                "w_value":"",
                "t0_timeout":"",
                "t1_timeout":"",
                "t2_timeout":"",
                "t3_timeout":""
            },
            "application_layer" : {
                "ca_asdu_size":"",
                "ioaddr_size":"",
                "asdu_size":"",
                "time_sync":true,
                "cmd_exec_timeout":"",
                "cmd_recv_timeout":"",
                "accept_cmd_with_time":"",
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":""
                    },
                    {
                       "orig_addr":""
                    },
                    {
                       "orig_addr":""
                    }
                ]
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1"
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });

    static string broken_protocol_stack_3 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.2168.2.244"
                          },
                          {
                             "clt_ip":"192.4168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"1922.168.2.224"
                          },
                          {
                             "clt_ip":"1192.168.0.11"
                          },
                          {
                             "clt_ip":"592.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"01.0.0.0",
                "port":32404,
                "tls":3,
                "k_value":112352,
                "w_value":344448,
                "t0_timeout":13450,
                "t1_timeout":1344445,
                "t2_timeout":14560,
                "t3_timeout":-211130
            },
            "application_layer" : {
                "ca_asdu_size":-2,
                "ioaddr_size":-23,
                "asdu_size":-3,
                "time_sync":false,
                "cmd_exec_timeout":202,
                "cmd_recv_timeout":620,
                "accept_cmd_with_time":1232,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":-2
                    },
                    {
                       "orig_addr":-11
                    },
                    {
                       "orig_addr":-2
                    }
                ]
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1"
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });

    static string broken_protocol_stack_4 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":0,
                "tls":"",
                "k_value":32769,
                "w_value":32769,
                "t0_timeout":257,
                "t1_timeout":257,
                "t2_timeout":257,
                "t3_timeout":-2
            },
            "application_layer" : {
                "ca_asdu_size":4,
                "ioaddr_size":5,
                "asdu_size":8,
                "time_sync":"",
                "cmd_exec_timeout":202,
                "cmd_recv_timeout":620,
                "accept_cmd_with_time":1232,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":256
                    },
                ]
                "asdu_queue_size":8,
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1"
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });


    static string broken_protocol_stack_5 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups" : "sd",
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":0,
                "tls":"",
                "k_value":32769,
                "w_value":32769,
                "t0_timeout":257,
                "t1_timeout":257,
                "t2_timeout":257,
                "t3_timeout":-2
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1"
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });
       static string broken_protocol_stack_6 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1"
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });

    static string broken_protocol_stack_7 = QUOTE({
        "prot2ocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":2404,
                "tls":false,
                "k_value":12,
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "asdu_queue_size": -1,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ]
            }
        }
    });


    static string broken_protocol_stack_9 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":2404,
                "tls":false,
                "k_value":12,
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "asdu_queue_size": 10,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ]
            }
        }
    });


    static string broken_protocol_stack_10 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":2404,
                "tls":false,
                "k_value":12,
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ]
            }
        }
    });

static string broken_protocol_stack_11 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":2404,
                "tls":false,
                "k_value":12,
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":"",
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "asdu_queue_size": "asd",
                "filter_list":""
            }
        }
    });


static string broken_protocol_stack_12 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":-1,
                "tls":true,
                "k_value":12,
                "mode":"no",
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ]
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1",
                    "asset": 231
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });

static string broken_protocol_stack_13 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":-1,
                "tls":true,
                "k_value":12,
                "mode":"no",
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "filter_list":[
                    2,2
                ]
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1",
                    "asset": 231
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });

static string broken_protocol_stack_14 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":-1,
                "tls":true,
                "k_value":12,
                "mode":"no",
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":20,
                "cmd_recv_timeout":60,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ],
                "asdu_queue_size":-1
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1",
                    "asset": 231
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });


static string broken_protocol_stack_15 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":-1,
                "tls":true,
                "k_value":12,
                "mode":"no",
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":-1,
                "cmd_recv_timeout":-1,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ],
                "cmd_dest": "a"
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1",
                    "asset": 231
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });

static string broken_protocol_stack_16 = QUOTE({
        "protocol_stack" : {
            "name" : "iec104server",
            "version" : "1.0",
            "transport_layer" : {
                "redundancy_groups":[
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.244"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          }
                       ],
                       "rg_name":"red-group-1"
                    },
                    {
                       "connections":[
                          {
                             "clt_ip":"192.168.2.224"
                          },
                          {
                             "clt_ip":"192.168.0.11"
                          },
                          {
                             "clt_ip":"192.168.0.12"
                          }
                       ],
                       "rg_name":"red-group-2"
                    },
                    {
                        "rg_name":"catch-all"
                    }
                ],
                "bind_on_ip":false,
                "srv_ip":"0.0.0.0",
                "port":-1,
                "tls":true,
                "k_value":12,
                "mode":"no",
                "w_value":8,
                "t0_timeout":10,
                "t1_timeout":15,
                "t2_timeout":10,
                "t3_timeout":20
            },
            "application_layer" : {
                "ca_asdu_size":2,
                "ioaddr_size":3,
                "asdu_size":0,
                "time_sync":false,
                "cmd_exec_timeout":-1,
                "cmd_recv_timeout":-1,
                "accept_cmd_with_time":2,
                "filter_orig":false,
                "filter_list":[
                    {
                       "orig_addr":0
                    },
                    {
                       "orig_addr":1
                    },
                    {
                       "orig_addr":2
                    }
                ],
                "cmd_dest": 3
            },
            "south_monitoring": [
                {
                    "connx_status": "CONSTAT-1",
                    "gi_status": "GISTAT-1",
                    "asset": 231
                },
                {
                    "connx_status": "CONSTAT-2",
                    "gi_status": "GISTAT-2"
                }
            ]
        }
    });


static string tls = QUOTE({
        "tls_conf" : {
            "private_key" : "iec104_server.key",
            "own_cert" : "iec104_server.cer",
            "ca_certs" : [
                {
                    "cert_file": "iec104_ca.cer"
                },
                {
                    "cert_file": "iec104_ca2.cer"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "iec104_client.cer"
                }
            ]
        }
    });

static string tls_2 = QUOTE({
        "tls_conf" : {
            "private_key" : "iec104_server.key",
            "own_cert" : "iec104_server.cer",
            "remote_certs" : [
                {
                    "cert_file": "iec104_client.cer"
                }
            ]
        }
    });

static string tls_3 = QUOTE({
        "tls_conf" : {
            "private_key" : "iec104_server.key",
            "own_cert" : "iec104_server.cer",
            "ca_certs" : [
                {
                    "cert_file": "iec104_ca.cer"
                }
            ]
        }
    });

static string tls_4 = QUOTE({
        "tls_conf" : {
            "private_key" : "iec104_server.key",
            "own_cert" : "iec104_server.cer"
        }
    });

static string tls_5 = QUOTE({
        "tls_conf" : {
            "private_key" : "iec104_server.key",
            "own_cert" : "iec104_server.cer",
            "ca_certs" : [
                {
                    "cert_file": "iec104_ca.cer"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "iec104_client.cer"
                }
            ]
        }
    });

static string tls_6 = QUOTE({
        "tls_conf" : {}
    });

static string tls_7 = QUOTE({
        "tls_conf" : {
            "private_key" : "iec104_server.key",
            "own_cert" : "iec104_server.cer",
            "ca_certs" : [
                {
                    "cert_file": "test1_CA.cert"
                }
            ]
        }
    });

static string tls_8 = QUOTE({
        "tls_conf" : {
            "private_key" : "test1_server.key",
            "own_cert" : "test1_server.cert",
            "ca_certs" : [
                {
                    "cert_file": ""
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test1_client.cert"
                }
            ]
        }
    });

static string tls_9 = QUOTE({
        "tls_conf" : {
            "private_key" : "test1_server.key",
            "own_cert" : "test1_server.cert",
            "ca_certs" : [
                {
                    "cert_file": "wrongcert.cert"
                }
            ]
        }
    });

static string tls_10 = QUOTE({
        "tls_conf" : {
            "private_key" : "test1_server.key",
            "own_cert" : "test1_server.cert",
            "ca_certs" : [
                {
                    "cert_file": "iec104_ca.cer"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test1_client.cert"
                }
            ]
        }
    });

static string tls_11 = QUOTE({
        "tls_conf" : {
            "private_key" : "test1_server.key",
            "own_cert" : "test1_server.cert",
            "remote_certs" : [
                {
                    "cert_file": "test1_client.cert"
                }
            ]
        }
    });

static string tls_test1 = QUOTE({
        "tls_conf" : {
            "private_key" : "test1_server.key",
            "own_cert" : "test1_server.cert",
            "ca_certs" : [
                {
                    "cert_file": "test1_CA.cert"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test1_client.cert"
                }
            ]
        }
    });

static string tls_test2 = QUOTE({
        "tls_conf" : {
            "private_key" : "test2_server.key",
            "own_cert" : "test2_server.crt",
            "ca_certs" : [
                {
                    "cert_file": "test2_CA.crt"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test2_client.crt"
                }
            ]
        }
    });

static string tls_test3 = QUOTE({
        "tls_conf" : {
            "private_key" : "test3_server.key",
            "own_cert" : "test3_server.pem",
            "ca_certs" : [
                {
                    "cert_file": "test3_CA.pem"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test3_client.pem"
                }
            ]
        }
    });

static string tls_test4 = QUOTE({
        "tls_conf" : {
            "private_key" : "test4_server.key",
            "own_cert" : "test4_server.p12",
            "ca_certs" : [
                {
                    "cert_file": "test4_CA.p12"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test4_client.p12"
                }
            ]
        }
    });

static string tls_test5 = QUOTE({
        "tls_conf" : {
            "private_key" : "test5_server.key",
            "own_cert" : "test5_server.der",
            "ca_certs" : [
                {
                    "cert_file": "test5_CA.der"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test5_client.der"
                }
            ]
        }
    });

static string tls_test6 = QUOTE({
        "tls_conf" : {
            "private_key" : "test6_server.pem",
            "own_cert" : "test6_server.cert",
            "ca_certs" : [
                {
                    "cert_file": "test6_CA.cert"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test6_client.cert"
                }
            ]
        }
    });

static string tls_test7 = QUOTE({
        "tls_conf" : {
            "private_key" : "test7_server.pem",
            "own_cert" : "test7_server.crt",
            "ca_certs" : [
                {
                    "cert_file": "test7_CA.crt"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test7_client.crt"
                }
            ]
        }
    });

static string tls_test8 = QUOTE({
        "tls_conf" : {
            "private_key" : "test8_server_key.pem",
            "own_cert" : "test8_server_cert.pem",
            "ca_certs" : [
                {
                    "cert_file": "test8_CA_cert.pem"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test8_client_cert.pem"
                }
            ]
        }
    });

static string tls_test9 = QUOTE({
        "tls_conf" : {
            "private_key" : "test9_server.pem",
            "own_cert" : "test9_server.p12",
            "ca_certs" : [
                {
                    "cert_file": "test9_CA.p12"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test9_client.p12"
                }
            ]
        }
    });

static string tls_test10 = QUOTE({
        "tls_conf" : {
            "private_key" : "test10_server.pem",
            "own_cert" : "test10_server.der",
            "ca_certs" : [
                {
                    "cert_file": "test10_CA.der"
                }
            ],
            "remote_certs" : [
                {
                    "cert_file": "test10_client.der"
                }
            ]
        }
    });

static string exchanged_data = QUOTE({
        "exchanged_data" : {
            "name" : "iec104server",
            "version" : "1.0",
            "datapoints":[
                {
                    "label":"TS1",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-672",
                          "typeid":"M_SP_NA_1"
                       },
                       {
                          "name":"tase2",
                          "address":"S_114562",
                          "typeid":"Data_StateQTimeTagExtended"
                       }
                    ]
                },
                {
                    "label":"TM1",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-984",
                          "typeid":"M_ME_NA_1"
                       },
                       {
                          "name":"tase2",
                          "address":"S_114562",
                          "typeid":"Data_RealQ"
                       }
                    ]
                },
                {
                    "label":"CM1",
                    "protocols":[
                       {
                          "name":"iec104",
                          "address":"45-10005",
                          "typeid":"C_SC_NA_1",
                          "termination_timeout": 3000
                       }
                    ]
                }
            ]
        }
    });

static string exchanged_data_2 = QUOTE({
        "exchanged_data" : {
            "name" : "iec104server",
            "version" : "1.0",
            "datapoints":[
                {
                    "label":"CM1",
                    "protocols":[
                       {}
                    ]
                }
            ]
        }
    });

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
    }

    // TearDown is ran for every tests, so each variable are destroyed again
    void TearDown() override
    {
        iec104Server->stop();

        delete iec104Server;
    }
};

TEST_F(ConnectionHandlerTest, NormalConnection)
{
    iec104Server->setJsonConfig(protocol_stack, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    // Create connection
    connection = CS104_Connection_create("127.0.0.1", IEC_60870_5_104_DEFAULT_PORT);

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack1)
{
    iec104Server->setJsonConfig(broken_protocol_stack_1, exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack2)
{
    iec104Server->setJsonConfig(broken_protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack3)
{
    iec104Server->setJsonConfig(broken_protocol_stack_3, exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack4)
{
    iec104Server->setJsonConfig(broken_protocol_stack_4, exchanged_data, tls);
    iec104Server->startSlave();
}
TEST_F(ConnectionHandlerTest, BrokenProtocolStack5)
{
    iec104Server->setJsonConfig(broken_protocol_stack_5, exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack6)
{
    iec104Server->setJsonConfig(broken_protocol_stack_6, exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack7)
{
    iec104Server->setJsonConfig(broken_protocol_stack_7, exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack8)
{
    iec104Server->setJsonConfig("", exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack9)
{
    iec104Server->setJsonConfig(broken_protocol_stack_9, exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack10)
{
    iec104Server->setJsonConfig(broken_protocol_stack_10, exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack11)
{
    iec104Server->setJsonConfig(broken_protocol_stack_11, exchanged_data, tls);
    iec104Server->startSlave();
}


TEST_F(ConnectionHandlerTest, BrokenProtocolStack12)
{
    iec104Server->setJsonConfig(broken_protocol_stack_12, exchanged_data, tls);
    iec104Server->startSlave();
}


TEST_F(ConnectionHandlerTest, BrokenProtocolStack13)
{
    iec104Server->setJsonConfig(broken_protocol_stack_13, exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack14)
{
    iec104Server->setJsonConfig(broken_protocol_stack_14, exchanged_data, tls);
    iec104Server->startSlave();
}


TEST_F(ConnectionHandlerTest, BrokenProtocolStack15)
{
    iec104Server->setJsonConfig(broken_protocol_stack_15, exchanged_data, tls);
    iec104Server->startSlave();
}

TEST_F(ConnectionHandlerTest, BrokenProtocolStack16)
{
    iec104Server->setJsonConfig(broken_protocol_stack_16, exchanged_data, tls);
    iec104Server->startSlave();
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST_F(ConnectionHandlerTest, TLSConnectionNoClientCertificates)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection

    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);

    Thread_sleep(2000);

    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);

}




/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////



TEST_F(ConnectionHandlerTest, TLSConnectionEmptyClientCertificates)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionEmptyClientKey)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnection)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionEmptyClientCACert)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_3 );
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionEmptyClientRemoteCert)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionNoRemoteOrCaCertificate)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();


    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_4);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}


TEST_F(ConnectionHandlerTest, TLSConnectionNoCaCertificate)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_3);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionKeyNotFound)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/wrongkey.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionOwnCertNotFound)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/wrongcert.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionCACertNotFound)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/wrongcert.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionRemoteCertNotFound)
{
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/wrongcert.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

TEST_F(ConnectionHandlerTest, TLSConnectionKeyDotKeyCertificateDotCert) {

    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/test1_CA.cert");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/test1_client.cert");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/test1_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/test1_server.cert");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_test1);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);

}

TEST_F(ConnectionHandlerTest, TLSConnectionKeyDotKeyCertificateDotCrt) {

    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/test2_CA.crt");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/test2_client.crt");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/test2_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/test2_server.crt");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_test2);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);

}


TEST_F(ConnectionHandlerTest, TLSConnectionKeyDotKeyCertificateDotP12) {

    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/test4_CA.p12");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/test4_client.p12");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/test4_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/test4_server.p12");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_test4);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);

}

TEST_F(ConnectionHandlerTest, TLSConnectionKeyDotKeyCertificateDotDer) {

    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/test5_CA.der");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/test5_client.der");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/test5_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/test5_server.der");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_test5);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);

}

TEST_F(ConnectionHandlerTest, TLSConnectionKeyDotPemCertificateDotCert) {

    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/test6_CA.cert");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/test6_client.cert");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/test6_client.pem", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/test6_server.cert");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_test6);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);

}


TEST_F(ConnectionHandlerTest, TLSConnectionKeyDotPemCertificateDotP12) {

    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/test9_CA.p12");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/test9_client.p12");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/test9_client.pem", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/test9_server.p12");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_test9);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);

}

TEST_F(ConnectionHandlerTest, TLSConnectionKeyDotPemCertificateDotDer) {

    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/test10_CA.der");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/test10_client.der");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/test10_client.pem", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/test10_server.der");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_test10);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */
    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);

}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////


TEST_F(ConnectionHandlerTest, TLSConnectionNoChainValidation_CF_ST) {

    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, false);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionNoChainValidation_CF_SF) {

    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, false);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_2);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

static void tlsEventHandler(void* parameter, TLSEventLevel eventLevel, int eventCode, const char* message, TLSConnection con)
{
    printf("TLS(client): level: %i code: %i message: %s\n", eventLevel, eventCode, message);
}

TEST_F(ConnectionHandlerTest, TLSConnectionOnlyKnownCertsFalse) {

    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_setEventHandler(tlsConfig, tlsEventHandler, NULL);

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/test1_CA.cert");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/test1_client.cert");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/test1_client.key", NULL);
    // TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/test1_server.cert");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);


    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_test1);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionNoServerCertificates) {
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_6);

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionNoServerCACertificate) {
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_CA.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_4);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionServerCACertificateDoesntExist) {
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/test1_CA.cert");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/test1_client.cert");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/test1_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/test1_server.cert");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, false);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_9);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionWrongServerCACertificate) {
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    // TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data, tls_7);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);

    CS104_Connection_sendStartDT(connection);

    InformationObject sc = (InformationObject)SingleCommand_create(NULL, 23005, true, false, 0);

    CS104_Connection_sendProcessCommandEx(connection, CS101_COT_ACTIVATION, 45, sc);

    InformationObject_destroy(sc);

    Thread_sleep(2000);

    ASSERT_FALSE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionStackRedundancyGroupsNotArray) {
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_3, exchanged_data, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}

TEST_F(ConnectionHandlerTest, TLSConnectionExchangeDataWrongDatapoints) {
    setenv("FLEDGE_DATA", "./tests/data", 1);

    TLSConfiguration tlsConfig = TLSConfiguration_create();

    TLSConfiguration_addCACertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_ca.cer");
    TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.cer");
    TLSConfiguration_setOwnKeyFromFile(tlsConfig, "tests/data/etc/certs/iec104_client.key", NULL);
    TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "tests/data/etc/certs/iec104_server.cer");
    TLSConfiguration_setChainValidation(tlsConfig, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(tlsConfig, true);

    // Create connection
    connection = CS104_Connection_createSecure("127.0.0.1", IEC_60870_5_104_DEFAULT_TLS_PORT, tlsConfig);

    iec104Server->setJsonConfig(protocol_stack_2, exchanged_data_2, tls);
    iec104Server->startSlave();

    Thread_sleep(500); /* wait for the server to start */

    bool result = CS104_Connection_connect(connection);
    ASSERT_TRUE(result);

    CS104_Connection_destroy(connection);
    TLSConfiguration_destroy(tlsConfig);
}
