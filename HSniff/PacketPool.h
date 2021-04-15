#pragma once

#include <map>
#include <WinSock2.h>
#include "Packet.h"


//��map���ݽṹ�洢���ݰ�
class PacketPool
{
private:
	std::map<int, Packet> m_pkts;		// �洢���ݰ���keyΪ���ݰ���ţ�valueΪ���ݰ�

public:
	PacketPool();
	~PacketPool();

	void add(const struct pcap_pkthdr* header, const u_char* pkt_data);
	void add(const Packet& pkt);
	void remove(int pktNum);
	void clear();
	Packet& get(int pktNum);
	Packet& getLast();
	int getSize() const;
	bool isEmpty() const;
};


