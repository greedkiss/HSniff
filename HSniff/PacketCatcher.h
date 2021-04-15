#pragma once

#include "PacketPool.h"
#include "pcap.h"


const int MODE_CAPTURE_LIVE = 0;
const int MODE_CAPTURE_OFFLINE = 1;

#define WM_PKTCATCH	(WM_USER + 100)
#define WM_TEXIT	(WM_USER + 101)
//������ʱ��ĳ�ʱʱ��
const int READ_PACKET_TIMEOUT = 1000;
// �������ڲ������ݰ�
class PacketCatcher
{
private:
	pcap_t* m_adhandle;	// ����������
	PacketPool* m_pool;		// ���ݰ��ص�ָ��
	pcap_dumper_t* m_dumper;		// ת���ļ�������
	CString	m_dev;			// ����/�ļ���Ϣ

public:
	PacketCatcher();
	PacketCatcher(PacketPool* pool);
	~PacketCatcher();

	bool setPool(PacketPool* pool);
	bool openAdapter(int devIndex, const CTime& currentTime);
	bool openAdapter(CString path);
	bool closeAdapter();
	void startCapture(int mode);
	void stopCapture();
	CString getDevName();
};

