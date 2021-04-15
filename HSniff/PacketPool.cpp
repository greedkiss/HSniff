#include "pch.h"
#include "PacketPool.h"


PacketPool::PacketPool()
{
}

PacketPool::~PacketPool()
{
}

//������ݵ�Pool
void PacketPool::add(const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	if (header && pkt_data)
	{
		int pktNum = 1 + m_pkts.size();
		Packet pkt(header, pkt_data, pktNum);
		m_pkts[pktNum] = pkt;
	}
}

//������ݰ�
void PacketPool::add(const Packet& pkt) {
	if (!pkt.isEmpty())
		m_pkts[pkt.num] = pkt;
}

//ɾ�����ݰ�
void PacketPool::remove(int pktNum)
{
	if (pktNum < 1 || pktNum > m_pkts.size())
		return;
	m_pkts.erase(pktNum);
}

//����������ݰ�
void PacketPool::clear()
{
	if (m_pkts.size() > 0)
		m_pkts.clear();
}

//�������ݰ��������ȡ���ݰ�
Packet& PacketPool::get(int pktNum)
{
	if (m_pkts.count(pktNum) > 0)
		return m_pkts[pktNum];
	return Packet();
}

//��ȡ���һ�����ݰ�
Packet& PacketPool::getLast()
{
	if (m_pkts.count(m_pkts.size()) > 0)
		return m_pkts[m_pkts.size()];
	return Packet();
}

//��ȡ���ݰ�����
int PacketPool::getSize() const
{
	return m_pkts.size();
}

//�ж��Ƿ������ݰ�
bool PacketPool::isEmpty() const
{
	if (m_pkts.size())
		return false;
	return true;
}