
// HSniffDlg.h: 头文件
//

#pragma once
#include "PacketCatcher.h"
#include "PacketDumper.h"


// CHSniffDlg 对话框
class CHSniffDlg : public CDialogEx
{
// 构造
public:
	CHSniffDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_HSNIFF_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

	//控件
	CComboBox combo_dev;
	CComboBox combox_filter;
	CListCtrl listCtrl_packetList;
	CButton Button_start;
	CTreeCtrl treeCtrl_packet;
	CEdit edit_packet;

	//控件相关函数
	void initialComboBoxDevList();
	void initialComboBoxFilterList();
	void initialListCtrlPacketList();


	

	
	//文件操作
	bool createDirectory(const CString& dirPath);

	//数据包
	PacketCatcher catcher;
	PacketPool pool;

	//转储文件
	PacketDumper	pktDumper;

	/* 标志 */
	bool    pktCaptureFlag;
	bool	fileOpenFlag;
	CString openFileName;	// 保存打开文件的文件名


public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg LRESULT OnPktCatchMessage(WPARAM wParam, LPARAM lParam);
	//控件点击操作
	afx_msg void OnClickedList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCustomdrawList1(NMHDR* pNMHDR, LRESULT* pResult);

	//打印函数
	int printListCtrlPacketList(const Packet& pkt);
	int printListCtrlPacketList(PacketPool& pool);
	int printListCtrlPacketList(PacketPool& pool, const CString& filter);
	int printEditCtrlPacketBytes(const Packet& pkt);

	//转换函数
	CString	MACAddr2CString(const MAC_Address& addr);
	CString	IPAddr2CString(const IP_Address& addr);


	afx_msg void OnBnClickedButton3();
};
