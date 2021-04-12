
// HSniffDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "HSniff.h"
#include "HSniffDlg.h"
#include "afxdialogex.h"
#include "PacketCap.h"
#include <vector>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CHSniffDlg 对话框



CHSniffDlg::CHSniffDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_HSNIFF_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CHSniffDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, combo_dev);
	DDX_Control(pDX, IDC_COMBO2, combox_filter);
	DDX_Control(pDX, IDC_LIST2, listCtrl_packetList);
}

BEGIN_MESSAGE_MAP(CHSniffDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CHSniffDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CHSniffDlg 消息处理程序

BOOL CHSniffDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// 初始化代码
	initialComboBoxDevList();
	initialComboBoxFilterList();
	initialListCtrlPacketList();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CHSniffDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CHSniffDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CHSniffDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CHSniffDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CHSniffDlg::initialComboBoxDevList()
{
	combo_dev.AddString(_T("选择网络设备"));
	combo_dev.SetCurSel(0);

	pcap_if_t* dev = NULL;
	pcap_if_t* allDevs = NULL;
	if (pcap_findalldevs(&allDevs, NULL) == -1) {
		AfxMessageBox(_T("获取网卡列表失败"), MB_OK);
		return;
	}
	for (dev = allDevs; dev != NULL; dev = dev->next) {
		if (dev->description != NULL) {
			combo_dev.AddString((CString)dev->description);
		}
	}
}

void CHSniffDlg::initialComboBoxFilterList()
{
	std::vector<CString> filterList;
	filterList.push_back(L"Ethernet");
	filterList.push_back(L"IP");
	filterList.push_back(L"ARP");
	filterList.push_back(L"ICMP");
	filterList.push_back(L"TCP");
	filterList.push_back(L"UDP");
	filterList.push_back(L"DNS");
	filterList.push_back(L"DHCP");
	filterList.push_back(L"HTTP");

	combox_filter.AddString(_T("选择过滤器（可选）"));
	combox_filter.SetCurSel(0);

	for (int i = 0; i < filterList.size(); ++i)
		combox_filter.AddString(filterList[i]);
}

void CHSniffDlg::initialListCtrlPacketList() {
	CRect rect;
	listCtrl_packetList.GetWindowRect(&rect);

	int index = 0;
	listCtrl_packetList.InsertColumn(index, L"编号", LVCFMT_CENTER, rect.Width() * 0.05);
	listCtrl_packetList.InsertColumn(++index, L"时间", LVCFMT_CENTER, rect.Width() * 0.15);
	listCtrl_packetList.InsertColumn(++index, L"协议", LVCFMT_CENTER, rect.Width() * 0.05);
	listCtrl_packetList.InsertColumn(++index, L"长度", LVCFMT_CENTER, rect.Width() * 0.05);
	listCtrl_packetList.InsertColumn(++index, L"源MAC地址", LVCFMT_CENTER, rect.Width() * 0.175);
	listCtrl_packetList.InsertColumn(++index, L"目的MAC地址", LVCFMT_CENTER, rect.Width() * 0.175);
	listCtrl_packetList.InsertColumn(++index, L"源IP地址", LVCFMT_CENTER, rect.Width() * 0.175);
	listCtrl_packetList.InsertColumn(++index, L"目的IP地址", LVCFMT_CENTER, rect.Width() * 0.175);
}



