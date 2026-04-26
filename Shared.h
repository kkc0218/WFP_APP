#pragma once

#pragma once

// ============================================================================
// Kernel Mode / User Mode �б�
// ============================================================================
#ifdef __KERNEL_MODE__
    // Kernel Mode - WDK ��� ���
#include <ntdef.h>
#else
    // User Mode - Windows SDK ��� ���
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#endif

// ============================================================================
// ����̽� �̸� ����
// ============================================================================
#define DEVICE_NAME         L"\\Device\\WfpExampleDevice"
#define SYMBOLIC_LINK_NAME  L"\\??\\WfpExampleLink"

// ============================================================================
// GUID ���� - WFP Callout �ĺ���
// ============================================================================


#ifdef __KERNEL_MODE__

// �⺻ ���� Callout (ALE_AUTH_CONNECT_V4)
// {B180900E-B939-4E64-912A-63799634B03B}
DEFINE_GUID(GUID_MY_WFP_CALLOUT,
    0xb180900e, 0xb939, 0x4e64, 0x91, 0x2a, 0x63, 0x79, 0x96, 0x34, 0xb0, 0x3b);

// SNI Stream Callout (STREAM_V4) - TLS ClientHello SNI �Ľ̿�
// {C291A11F-CA4A-4F75-A23B-74889735C14C}
DEFINE_GUID(GUID_MY_WFP_SNI_CALLOUT,
    0xc291a11f, 0xca4a, 0x4f75, 0xa2, 0x3b, 0x74, 0x88, 0x97, 0x35, 0xc1, 0x4c);

// QUIC ���� Callout (DATAGRAM_DATA_V4) - QUIC Initial ��Ŷ SNI �Ľ̿� 
// {D382B22F-E5B1-4C6F-B430-56789ABCDE01}
DEFINE_GUID(GUID_MY_WFP_QUIC_CALLOUT,
    0xd382b22f, 0xe5b1, 0x4c6f, 0xb4, 0x30, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0x01);

// DNS ����͸� Callout (DATAGRAM_DATA_V4) - DNS ���� ����͸��� 
// {E493C330-F6C2-4D70-C541-67890BCDEF12}
DEFINE_GUID(GUID_MY_WFP_DNS_CALLOUT,
    0xe493c330, 0xf6c2, 0x4d70, 0xc5, 0x41, 0x67, 0x89, 0x0b, 0xcd, 0xef, 0x12);

// ALE Flow Established Callout 
// {F5A4D441-A7E3-5E81-D652-789A1CDEF023}
DEFINE_GUID(GUID_MY_WFP_FLOW_CALLOUT,
    0xf5a4d441, 0xa7e3, 0x5e81, 0xd6, 0x52, 0x78, 0x9a, 0x1c, 0xde, 0xf0, 0x23);

// DNS Sinkhole Callout - DNS ���� ������
// {A6B5E552-B8F4-6F92-E763-89AB2DEF1234}
DEFINE_GUID(GUID_MY_WFP_DNS_SINKHOLE_CALLOUT,
    0xa6b5e552, 0xb8f4, 0x6f92, 0xe7, 0x63, 0x89, 0xab, 0x2d, 0xef, 0x12, 0x34);

// v8.1: ALE_AUTH_RECV_ACCEPT Callout (Inbound PID cache)
// {B7C6F663-C905-7AA3-F874-9ABC3EF02345}
DEFINE_GUID(GUID_MY_WFP_RECV_ACCEPT_CALLOUT,
    0xb7c6f663, 0xc905, 0x7aa3, 0xf8, 0x74, 0x9a, 0xbc, 0x3e, 0xf0, 0x23, 0x45);

#endif // __KERNEL_MODE__

// ============================================================================
// IOCTL �ڵ� ����
// ============================================================================

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

// �⺻ PID ���� ����
#define IOCTL_WFP_SET_BLOCK_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ��Ŷ ĸó ��� (On/Off)
#define IOCTL_WFP_TOGGLE_CAPTURE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ��ġ ��Ŷ ������ ��ȸ
#define IOCTL_WFP_GET_PACKET_BATCH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ĸó ���� ��ȸ
#define IOCTL_WFP_GET_CAPTURE_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ��Ŷ ť �ʱ�ȭ (Ŭ����)
#define IOCTL_WFP_CLEAR_PACKET_QUEUE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ���� ���� (PID ����)
#define IOCTL_WFP_RESET_BLOCK_PID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// SNI ��� URL ���� IOCTL �ڵ�
// ============================================================================

// SNI URL ���� �߰�/���� (���)
#define IOCTL_WFP_SNI_BLOCK_URL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

// SNI ���� ����Ʈ ��ȸ
#define IOCTL_WFP_SNI_GET_BLOCK_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)

// SNI ���� ����Ʈ ��ü �ʱ�ȭ
#define IOCTL_WFP_SNI_CLEAR_BLOCK_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

// SNI ���� Ȱ��ȭ/��Ȱ��ȭ
#define IOCTL_WFP_SNI_TOGGLE_BLOCKING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// Ȯ�� IOCTL �ڵ� 
// ============================================================================

// Ȯ�� ���� ��ȸ (QUIC/DNS ��� ����)
#define IOCTL_WFP_GET_CAPTURE_STATUS_EX \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IP ĳ�� ��ȸ (�����)
#define IOCTL_WFP_GET_IP_CACHE_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IP ĳ�� �ʱ�ȭ
#define IOCTL_WFP_CLEAR_IP_CACHE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// DNS Sinkhole IOCTL 
// ============================================================================

// DNS ��ũȦ Ȱ��ȭ/��Ȱ��ȭ
#define IOCTL_WFP_DNS_SINKHOLE_TOGGLE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)

// DNS ��ũȦ IP ����
#define IOCTL_WFP_DNS_SINKHOLE_SET_IP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)

// DNS ��ũȦ ���� ��ȸ
#define IOCTL_WFP_DNS_SINKHOLE_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// SNS ���� ���ε� ���� IOCTL �ڵ� (v7.0 - �� ��� DLP)
// ============================================================================

// v7.0: ������ ��� IOCTL ���� (UPLOAD_BLOCK_URL, UPLOAD_GET_BLOCK_LIST, UPLOAD_CLEAR_BLOCK_LIST, UPLOAD_ADD_PRESET)

// ���ε� ���� Ȱ��ȭ/��Ȱ��ȭ
#define IOCTL_WFP_UPLOAD_TOGGLE_BLOCKING \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x843, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ���ε� ���� ���� ��ȸ
#define IOCTL_WFP_UPLOAD_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x845, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ���ε� ���� �Ӱ谪 ����
#define IOCTL_WFP_UPLOAD_SET_THRESHOLD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x846, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ����͸� �� �߰� (v5.0 �ű�)
#define IOCTL_WFP_UPLOAD_ADD_APP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ����͸� �� ����
#define IOCTL_WFP_UPLOAD_REMOVE_APP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ����͸� �� ��� ��ȸ
#define IOCTL_WFP_UPLOAD_GET_APP_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x852, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ����͸� �� ��ü �ʱ�ȭ
#define IOCTL_WFP_UPLOAD_CLEAR_APP_LIST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x853, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ����͸� �� ������ �ϰ� ���
#define IOCTL_WFP_UPLOAD_ADD_APP_PRESET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x854, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// ============================================================================



// Driver / user-mode agent self-protection IOCTLs
#define IOCTL_WFP_SELF_PROTECT_SET_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WFP_SELF_PROTECT_CLEAR_PROCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x871, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WFP_SELF_PROTECT_GET_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x872, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ============================================================================
// ��� ����
// ============================================================================

// ��Ŷ ĸó ����
#define MAX_PACKETS_PER_BATCH   64      // ��ġ�� �ִ� ��Ŷ ��
#define PACKET_QUEUE_SIZE       256     // ����̹� ���� ť ũ�� (�� ����)

// SNI ���� ����
#define MAX_SNI_LENGTH          256     // �ִ� SNI ������ ����
#define MAX_BLOCKED_URLS        128     // �ִ� ���� URL ��
#define SNI_BLOCK_LIST_SIZE     32      // �� ���� ��ȯ�� ���� URL ��

// IP ĳ�� ���� ��� (v3.0 �ű�) - Kernel Mode���� ������ ����
#ifndef MAX_BLOCKED_IPS
#define MAX_BLOCKED_IPS         2048    // ���� IP ĳ�� ũ��
#endif

#ifndef IP_CACHE_TIMEOUT_SEC
#define IP_CACHE_TIMEOUT_SEC    1800    // IP ĳ�� ���� �ð� (30��)
#endif

// SNS ���� ���ε� ���� ���� ��� (v7.0 - �� ��� Flow Context)
#define UPLOAD_FLOW_WINDOW_SEC      30      // ���� ������ (30��)
#define UPLOAD_DEFAULT_THRESHOLD    102400   // �⺻ �Ӱ谪 100KB (����Ʈ) - �׽�Ʈ��

// ����͸� ��� �� ���� ��� (v5.0 �ű�)
#define MAX_MONITORED_APPS          32      // �ִ� ����͸� ��� �� ��
#define MAX_APP_NAME_LENGTH         64      // �� �̸� �ִ� ����

// QUIC �������� ���� ��� (v3.0 �ű�)
#ifndef QUIC_VERSION_1
#define QUIC_VERSION_1          0x00000001
#endif

#define QUIC_VERSION_2          0x6b3343cf

#ifndef QUIC_LONG_HEADER_MASK
#define QUIC_LONG_HEADER_MASK   0x80
#endif

#ifndef QUIC_INITIAL_TYPE
#define QUIC_INITIAL_TYPE       0x00
#endif

#define QUIC_DEFAULT_PORT       443

// DNS ���� ��� (v3.0 �ű�)
#define DNS_PORT                53
#define DNS_RESPONSE_FLAG       0x8000
#define DNS_MAX_NAME_LENGTH     255

// DNS Sinkhole ��� (v3.0 �ű�)
#define DNS_SINKHOLE_DEFAULT_IP     0x7F000001  // 127.0.0.1 (ȣ��Ʈ ����Ʈ ����)
#define DNS_SINKHOLE_HTTPS_PORT     443
#define DNS_SINKHOLE_HTTP_PORT      80



// Self-protection flags
#define SELF_PROTECT_FLAG_TERMINATE      0x00000001UL
#define SELF_PROTECT_FLAG_VM_READ        0x00000002UL
#define SELF_PROTECT_FLAG_VM_WRITE       0x00000004UL
#define SELF_PROTECT_FLAG_VM_OPERATION   0x00000008UL
#define SELF_PROTECT_FLAG_CREATE_THREAD  0x00000010UL
#define SELF_PROTECT_FLAG_DUP_HANDLE     0x00000020UL
#define SELF_PROTECT_FLAG_SUSPEND_RESUME 0x00000040UL
#define SELF_PROTECT_FLAG_ALL            \
    (SELF_PROTECT_FLAG_TERMINATE | SELF_PROTECT_FLAG_VM_READ | \
     SELF_PROTECT_FLAG_VM_WRITE | SELF_PROTECT_FLAG_VM_OPERATION | \
     SELF_PROTECT_FLAG_CREATE_THREAD | SELF_PROTECT_FLAG_DUP_HANDLE | \
     SELF_PROTECT_FLAG_SUSPEND_RESUME)


// ============================================================================
// �������� ��� (IPPROTO_*)
// ============================================================================
#define PROTO_ICMP      1
#define PROTO_TCP       6
#define PROTO_UDP       17

// ============================================================================
// ��Ŷ ���� ����
// ============================================================================
typedef enum _PACKET_DIRECTION {
    PACKET_DIR_OUTBOUND = 0,    // �۽� ��Ŷ
    PACKET_DIR_INBOUND = 1      // ���� ��Ŷ
} PACKET_DIRECTION;

// ============================================================================
// ��Ŷ �׼� ����
// ============================================================================
typedef enum _PACKET_ACTION {
    PACKET_ACTION_PERMIT = 0,   // ���
    PACKET_ACTION_BLOCK = 1     // ���ܵ�
} PACKET_ACTION;

// ============================================================================
// ���� Ÿ�� ���� (v3.0 �ű�)
// ============================================================================
typedef enum _BLOCK_TYPE {
    BLOCK_TYPE_NONE = 0,        // ���� ����
    BLOCK_TYPE_PID = 1,         // PID ��� ����
    BLOCK_TYPE_IP_CACHE = 2,    // IP ĳ�� ��� ����
    BLOCK_TYPE_SNI_TLS = 3,     // TLS SNI ��� ����
    BLOCK_TYPE_SNI_QUIC = 4,    // QUIC SNI ��� ����
    BLOCK_TYPE_DNS = 5,         // DNS ��� ����
    BLOCK_TYPE_DNS_SINKHOLE = 6, // DNS ��ũȦ �����̷��� (v3.0 �ű�)
    BLOCK_TYPE_UPLOAD = 7        // SNS ���� ���ε� ���� (v4.0 �ű�)
} BLOCK_TYPE;

// ============================================================================
// ������ ����ü ����
// ============================================================================

#pragma pack(push, 8)  // 8����Ʈ ���ķ� 32/64��Ʈ ȣȯ�� ����

// �⺻ PID ���� ���� ����ü
typedef struct _BLOCK_CONFIG {
    unsigned long ProcessId;
    unsigned long Reserved;     // ���Ŀ� �е�
} BLOCK_CONFIG, * PBLOCK_CONFIG;

// ĸó ��� ���� ����ü
typedef struct _CAPTURE_TOGGLE {
    unsigned long Enable;       // 0: ��Ȱ��ȭ, 1: Ȱ��ȭ
    unsigned long Reserved;     // ���Ŀ� �е�
} CAPTURE_TOGGLE, * PCAPTURE_TOGGLE;

// ĸó ���� ��ȸ ���� ����ü (�⺻ - ���� ȣȯ�� ����)
typedef struct _CAPTURE_STATUS {
    unsigned long IsCapturing;      // ���� ĸó ����
    unsigned long BlockedPid;       // ���� ���� ���� PID
    unsigned long QueuedPackets;    // ť�� ��� ���� ��Ŷ ��
    unsigned long TotalCaptured;    // �� ĸó�� ��Ŷ ��
    unsigned long TotalBlocked;     // �� ���ܵ� ��Ŷ ��
    unsigned long DroppedPackets;   // ť �����÷ο�� ��ӵ� ��Ŷ ��
    // SNI ���� ���
    unsigned long SniBlockingEnabled;   // SNI ���� Ȱ��ȭ ����
    unsigned long SniBlockedUrls;       // ��ϵ� ���� URL ��
    unsigned long SniTotalBlocked;      // SNI/QUIC�� ���ܵ� �� ���� ��
} CAPTURE_STATUS, * PCAPTURE_STATUS;

// Ȯ�� ĸó ���� ��ȸ ���� ����ü 
typedef struct _CAPTURE_STATUS_EX {
    // �⺻ �ʵ� (CAPTURE_STATUS�� ����)
    unsigned long IsCapturing;
    unsigned long BlockedPid;
    unsigned long QueuedPackets;
    unsigned long TotalCaptured;
    unsigned long TotalBlocked;
    unsigned long DroppedPackets;
    unsigned long SniBlockingEnabled;
    unsigned long SniBlockedUrls;
    unsigned long SniTotalBlocked;

    // Ȯ�� �ʵ� 
    unsigned long QuicBlockingEnabled;  // QUIC ���� Ȱ��ȭ ����
    unsigned long QuicTotalBlocked;     // QUIC���θ� ���ܵ� ���� ��
    unsigned long DnsMonitoringEnabled; // DNS ����͸� Ȱ��ȭ ����
    unsigned long DnsBasedBlocked;      // DNS ��� ���� ���� ��
    unsigned long IpCacheCount;         // IP ĳ�ÿ� ����� IP ��
    unsigned long IpCacheHits;          // IP ĳ�� ��Ʈ ��
    unsigned long Reserved[2];          // ���� Ȯ���
} CAPTURE_STATUS_EX, * PCAPTURE_STATUS_EX;

// ���� ��Ŷ ��Ÿ������ ����ü
typedef struct _PACKET_INFO {
    // Ÿ�ӽ����� (�ý��� �ð�, 100ns ����)
    unsigned __int64 Timestamp;

    // ���μ��� ����
    unsigned long ProcessId;

    // IP �ּ� (IPv4, ��Ʈ��ũ ����Ʈ ����)
    unsigned long LocalAddress;
    unsigned long RemoteAddress;

    // ��Ʈ (ȣ��Ʈ ����Ʈ ����)
    unsigned short LocalPort;
    unsigned short RemotePort;

    // �������� (TCP=6, UDP=17, ICMP=1)
    unsigned char Protocol;

    // ��Ŷ ���� (PACKET_DIRECTION)
    unsigned char Direction;

    // ��Ŷ �׼� (PACKET_ACTION)
    unsigned char Action;

    // ���� (���Ŀ�)
    unsigned char Reserved;

    // ��Ŷ ũ�� (����Ʈ)
    unsigned long PacketSize;

    // �߰� �е� (64��Ʈ ����)
    unsigned long Reserved2;

} PACKET_INFO, * PPACKET_INFO;

// ��Ŷ ��ġ �����̳� ����ü
typedef struct _PACKET_BATCH {
    // �� ��ġ�� ���Ե� ��Ŷ ��
    unsigned long PacketCount;

    // ť�� ���� ��Ŷ �� (�߰� ��ȸ �ʿ� ���� �Ǵܿ�)
    unsigned long RemainingPackets;

    // ������ ��ȣ (��ġ ������)
    unsigned long SequenceNumber;

    // ����
    unsigned long Reserved;

    // ��Ŷ ������ �迭
    PACKET_INFO Packets[MAX_PACKETS_PER_BATCH];

} PACKET_BATCH, * PPACKET_BATCH;

// ============================================================================
// SNI ���� ���� ����ü
// ============================================================================

// SNI URL ���� ��û ����ü
typedef struct _SNI_BLOCK_REQUEST {
    char Url[MAX_SNI_LENGTH];       // ������ URL (null-terminated)
    unsigned long Action;           // 0: �ڵ�(���), 1: �߰�, 2: ����
    unsigned long Reserved;         // ���Ŀ� �е�
} SNI_BLOCK_REQUEST, * PSNI_BLOCK_REQUEST;

// SNI ���� ��û �׼� ���
#define SNI_ACTION_TOGGLE   0   // ��� (������ ����, ������ �߰�)
#define SNI_ACTION_ADD      1   // �߰�
#define SNI_ACTION_REMOVE   2   // ����

// SNI ���� ���� ����ü
typedef struct _SNI_BLOCK_RESPONSE {
    unsigned long Success;          // ���� ����
    unsigned long IsBlocked;        // ���� ���� ���� (1: ���� ��, 0: ���� ������)
    unsigned long TotalBlockedUrls; // ��ü ���� URL ��
    unsigned long Reserved;         // ���Ŀ� �е�
} SNI_BLOCK_RESPONSE, * PSNI_BLOCK_RESPONSE;

// SNI ���� ����Ʈ ��ȸ ��û
typedef struct _SNI_LIST_REQUEST {
    unsigned long StartIndex;       // ���� �ε���
    unsigned long MaxCount;         // �ִ� ��ȯ ����
} SNI_LIST_REQUEST, * PSNI_LIST_REQUEST;

// SNI ���� URL ��Ʈ��
typedef struct _SNI_URL_ENTRY {
    char Url[MAX_SNI_LENGTH];       // URL
    unsigned long BlockCount;       // ���� Ƚ��
    unsigned long Reserved;         // ���Ŀ� �е�
} SNI_URL_ENTRY, * PSNI_URL_ENTRY;

// SNI ���� ����Ʈ ���� ����ü
typedef struct _SNI_LIST_RESPONSE {
    unsigned long TotalCount;       // ��ü ���� URL ��
    unsigned long ReturnedCount;    // �� ���信 ���Ե� URL ��
    unsigned long StartIndex;       // ���� �ε���
    unsigned long HasMore;          // �� ���� �׸� ���� ���� (v3.0: Reserved -> HasMore)
    SNI_URL_ENTRY Entries[SNI_BLOCK_LIST_SIZE]; // URL ��Ʈ�� �迭
} SNI_LIST_RESPONSE, * PSNI_LIST_RESPONSE;

// SNI ���� ��� ����ü
typedef struct _SNI_TOGGLE {
    unsigned long Enable;           // 0: ��Ȱ��ȭ, 1: Ȱ��ȭ
    unsigned long Reserved;         // ���Ŀ� �е�
} SNI_TOGGLE, * PSNI_TOGGLE;

// ============================================================================
// IP ĳ�� ���� ����ü 
// ============================================================================

// IP ĳ�� ��Ʈ�� (��ȸ��)
typedef struct _IP_CACHE_ENTRY {
    unsigned long IpAddress;        // IP �ּ� (��Ʈ��ũ ����Ʈ ����)
    char AssociatedSni[MAX_SNI_LENGTH]; // ����� SNI
    unsigned long HitCount;         // ��Ʈ Ƚ��
    unsigned long AgeSeconds;       // ĳ�ÿ� ����� �ð� (��)
} IP_CACHE_ENTRY, * PIP_CACHE_ENTRY;

// IP ĳ�� ���� ��ȸ ����
typedef struct _IP_CACHE_STATUS {
    unsigned long TotalEntries;     // ��ü ��Ʈ�� ��
    unsigned long MaxEntries;       // �ִ� ��Ʈ�� ��
    unsigned long TimeoutSeconds;   // ���� �ð� (��)
    unsigned long Reserved;
} IP_CACHE_STATUS, * PIP_CACHE_STATUS;

// ============================================================================
// DNS Sinkhole ���� ����ü (v3.0 �ű�)
// ============================================================================

// DNS ��ũȦ ��� ����ü
typedef struct _DNS_SINKHOLE_TOGGLE {
    unsigned long Enable;           // 0: ��Ȱ��ȭ, 1: Ȱ��ȭ
    unsigned long Reserved;         // ���Ŀ� �е�
} DNS_SINKHOLE_TOGGLE, * PDNS_SINKHOLE_TOGGLE;

// DNS ��ũȦ ���� ����ü
typedef struct _DNS_SINKHOLE_CONFIG {
    unsigned long SinkholeIp;       // ��ũȦ IP (ȣ��Ʈ ����Ʈ ����, �⺻��: 127.0.0.1)
    unsigned short HttpPort;        // HTTP ��Ʈ (�⺻��: 80)
    unsigned short HttpsPort;       // HTTPS ��Ʈ (�⺻��: 443)
    unsigned long Reserved;         // ���Ŀ� �е�
} DNS_SINKHOLE_CONFIG, * PDNS_SINKHOLE_CONFIG;

// DNS ��ũȦ ���� ��ȸ ���� ����ü
typedef struct _DNS_SINKHOLE_STATUS {
    unsigned long Enabled;              // Ȱ��ȭ ����
    unsigned long SinkholeIp;           // ���� ��ũȦ IP
    unsigned short HttpPort;            // ���� HTTP ��Ʈ
    unsigned short HttpsPort;           // ���� HTTPS ��Ʈ
    unsigned long long TotalRedirected; // �� �����̷��ǵ� ���� ��
    unsigned long long TotalDnsModified;// �� ������ DNS ���� ��
    unsigned long Reserved[2];          // ���� Ȯ���
} DNS_SINKHOLE_STATUS, * PDNS_SINKHOLE_STATUS;

// ============================================================================
// SNS ���� ���ε� ���� ���� ����ü (v7.0 - �� ��� DLP)
// ============================================================================

// �� ������ Ÿ�� ���� (v5.0 �ű�)
typedef enum _APP_PRESET_TYPE {
    APP_PRESET_BROWSERS = 0,    // ������ (chrome, edge, firefox ��)
    APP_PRESET_MESSENGERS = 1,  // �޽��� (kakaotalk, line, telegram ��)
    APP_PRESET_ALL = 99         // ��� ������ �ϰ� ���
} APP_PRESET_TYPE;

// ���ε� ���� ��� ����ü
typedef struct _UPLOAD_TOGGLE {
    unsigned long Enable;           // 0: ��Ȱ��ȭ, 1: Ȱ��ȭ
    unsigned long Reserved;         // ���Ŀ� �е�
} UPLOAD_TOGGLE, * PUPLOAD_TOGGLE;

// ���ε� ���� ���� ��ȸ ���� ����ü
typedef struct _UPLOAD_BLOCK_STATUS {
    unsigned long Enabled;              // Ȱ��ȭ ����
    unsigned long Reserved1;            // v7.0: ������ ����Ʈ ���� (���� TotalDomains)
    unsigned long long TotalBlocked;    // �� ���ܵ� ���� ��
    unsigned long ThresholdBytes;       // ���� �Ӱ谪 (����Ʈ)
    unsigned long WindowSeconds;        // ���� ������ (��)
    unsigned long ActiveFlows;          // ���� ���� ���� Flow Context ��
    unsigned long MonitoredApps;        // ����͸� ��� �� ��
    unsigned long Reserved2;            // ���Ŀ� �е�
} UPLOAD_BLOCK_STATUS, * PUPLOAD_BLOCK_STATUS;

// ���ε� ���� �Ӱ谪 ���� ����ü
typedef struct _UPLOAD_THRESHOLD_CONFIG {
    unsigned long ThresholdBytes;       // �Ӱ谪 (����Ʈ, 0�̸� �⺻�� ���)
    unsigned long WindowSeconds;        // ���� ������ (��, 0�̸� �⺻�� ���)
    unsigned long Reserved[2];          // ���Ŀ� �е�
} UPLOAD_THRESHOLD_CONFIG, * PUPLOAD_THRESHOLD_CONFIG;

// ============================================================================
// ����͸� ��� �� ���� ����ü (v5.0 �ű�)
// ============================================================================

// ����͸� �� �߰�/���� ��û ����ü
typedef struct _MONITORED_APP_REQUEST {
    char AppName[MAX_APP_NAME_LENGTH];  // �� ���� ���ϸ� (��: "chrome.exe")
    unsigned long Action;               // 0: �ڵ�(���), 1: �߰�, 2: ����
    unsigned long Reserved;             // ���Ŀ� �е�
} MONITORED_APP_REQUEST, * PMONITORED_APP_REQUEST;

// ����͸� �� �߰�/���� ���� ����ü
typedef struct _MONITORED_APP_RESPONSE {
    unsigned long Success;              // ���� ����
    unsigned long TotalApps;            // ���� ��ü ����͸� �� ��
    unsigned long Reserved[2];          // ���Ŀ� �е�
} MONITORED_APP_RESPONSE, * PMONITORED_APP_RESPONSE;

// ����͸� �� ��Ʈ�� (����� ����)
typedef struct _MONITORED_APP_ENTRY_USER {
    char AppName[MAX_APP_NAME_LENGTH];  // �� ���� ���ϸ�
    unsigned long ActiveFlows;          // �ش� ���� Ȱ�� �÷ο� ��
    unsigned long Reserved;             // ���Ŀ� �е�
} MONITORED_APP_ENTRY_USER, * PMONITORED_APP_ENTRY_USER;

// ����͸� �� ��� ���� ����ü
typedef struct _MONITORED_APP_LIST_RESPONSE {
    unsigned long TotalCount;           // ��ü �� ��
    unsigned long ReturnedCount;        // �� ���信 ���Ե� �� ��
    unsigned long Reserved[2];          // ���Ŀ� �е�
    MONITORED_APP_ENTRY_USER Entries[MAX_MONITORED_APPS]; // �� ��Ʈ�� �迭
} MONITORED_APP_LIST_RESPONSE, * PMONITORED_APP_LIST_RESPONSE;

// �� ������ �߰� ��û ����ü
typedef struct _APP_PRESET_REQUEST {
    unsigned long PresetType;           // APP_PRESET_TYPE ��
    unsigned long Reserved;             // ���Ŀ� �е�
} APP_PRESET_REQUEST, * PAPP_PRESET_REQUEST;

// �� ������ �߰� ���� ����ü
typedef struct _APP_PRESET_RESPONSE {
    unsigned long Success;              // ���� ����
    unsigned long AddedCount;           // �߰��� �� ��
    unsigned long TotalApps;            // ��ü ����͸� �� ��
    unsigned long Reserved;             // ���Ŀ� �е�
} APP_PRESET_RESPONSE, * PAPP_PRESET_RESPONSE;

// ============================================================================
// Driver / User-mode Agent self-protection (Anti-Tampering)
// ============================================================================

typedef struct _SELF_PROTECT_CONFIG {
    unsigned long ProcessId;
    unsigned long ProtectionFlags;
    unsigned long Reserved1;
    unsigned long Reserved2;
} SELF_PROTECT_CONFIG, * PSELF_PROTECT_CONFIG;

typedef struct _SELF_PROTECT_STATUS {
    unsigned long Enabled;
    unsigned long ProtectedPid;
    unsigned long ProtectionFlags;
    unsigned long CallbackReady;
    unsigned __int64 BlockedOpenAttempts;
    unsigned __int64 BlockedTerminateAttempts;
} SELF_PROTECT_STATUS, * PSELF_PROTECT_STATUS;

// ============================================================================
// ============================================================================