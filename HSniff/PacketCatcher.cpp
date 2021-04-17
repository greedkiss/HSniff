#include "pch.h"
#include "PacketCatcher.h"
#include "Packet.h"
#include "Thread.h"


PacketCatcher::PacketCatcher()
{
	m_adhandle = NULL;
	m_pool = NULL;
	m_dumper = NULL;
}

PacketCatcher::PacketCatcher(PacketPool* pool)
{
	m_adhandle = NULL;
	m_pool = pool;
	m_dumper = NULL;
}

PacketCatcher::~PacketCatcher()
{
	m_adhandle = NULL;
	m_pool = NULL;
	m_dumper = NULL;
}

bool PacketCatcher::setPool(PacketPool* pool)
{
	if (pool)
	{
		m_pool = pool;
		return true;
	}
	return false;
}

//������������ļ�������
bool PacketCatcher::openAdapter(int devIndex, const CTime& currentTime)
{
	if (devIndex < 0 || m_adhandle) {
		return false;
	}

	int count = 0;
	int selDev = devIndex - 1;
	pcap_if_t* dev, * allDevs;

	if (pcap_findalldevs(&allDevs, NULL) == -1) {
		AfxMessageBox(L"���������豸����", MB_OK);
		return false;
	}

	for (dev = allDevs; count < selDev; dev = dev->next, count++);
	//������Ϣ
	m_dev = CString(" ( ") + dev->name + CString(" )");

	// ������
	if ((m_adhandle = pcap_open_live(dev->name,
		65535,						// ��󲶻񳤶�
		PCAP_OPENFLAG_PROMISCUOUS,	// ��������Ϊ����ģʽ 
		READ_PACKET_TIMEOUT,		// ��ȡ��ʱʱ��
		NULL)) == NULL)
	{
		AfxMessageBox(_T("pcap_open_live����!"), MB_OK);
		return false;
	}

	/* ��ת���ļ� */
	CString file = L"HSniff" + currentTime.Format("%Y%m%d%H%M%S") + L".pcap";
	CString path = L"E:\\project\\HSniff\\HSniff\\tmp" + file;
	
	char* char_path = (LPSTR)(LPCTSTR)path;

	m_dumper = pcap_dump_open(m_adhandle, char_path);

	pcap_freealldevs(allDevs);
	return true;
}

//�����ļ�����ļ�������
bool PacketCatcher::openAdapter(CString path)
{
	if (path.IsEmpty())
		return false;
	m_dev = path;

	char* char_path = (LPSTR)(LPCTSTR)path;

	if ((m_adhandle = pcap_open_offline(char_path, NULL)) == NULL)
	{
		AfxMessageBox(_T("pcap_open_offline����!"), MB_OK);
		return false;
	}
	return true;
}

//�ر�����
bool PacketCatcher::closeAdapter()
{
	if (m_adhandle)
	{
		pcap_close(m_adhandle);
		m_adhandle = NULL;
		if (m_dumper)
		{
			pcap_dump_close(m_dumper);
			m_dumper = NULL;
		}
		return true;
	}
	return false;
}

//������
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ThreadParam* threadParam = (ThreadParam*)param;

	switch (threadParam->m_mode)
	{
	case MODE_CAPTURE_LIVE:
	{
		threadParam->m_pool->add(header, pkt_data);
		pcap_dump((u_char*)threadParam->m_dumper, header, pkt_data);
		break;
	}
	case MODE_CAPTURE_OFFLINE:
	{
		threadParam->m_pool->add(header, pkt_data);
		break;
	}
	}

	PostMessage(AfxGetMainWnd()->m_hWnd, WM_PKTCATCH, NULL, (LPARAM)(threadParam->m_pool->getLast().num));

	// ��������ץ���������߳�˯��0.1�룬��ֹ���濨��
	if (threadParam->m_mode == MODE_CAPTURE_LIVE) {
		Sleep(100);
	}
}

UINT capture_thread(LPVOID pParam)
{
	ThreadParam* p = (ThreadParam*)pParam;

	/* ��ʼ�������ݰ� */
	pcap_loop(p->m_adhandle, -1, packet_handler, (unsigned char*)p);
	PostMessage(AfxGetMainWnd()->m_hWnd, WM_TEXIT, NULL, NULL);
	return 0;
}

//��ʼץ��
void PacketCatcher::startCapture(int mode)
{
	if (m_adhandle && m_pool)
		AfxBeginThread(capture_thread, new ThreadParam(m_adhandle, m_pool, m_dumper, mode));
}

//ֹͣץ��
void PacketCatcher::stopCapture()
{
	if (m_adhandle)
		pcap_breakloop(m_adhandle);
}

CString PacketCatcher::getDevName()
{
	return m_dev;
}
