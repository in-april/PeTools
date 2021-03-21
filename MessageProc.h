#pragma once
#include "framework.h"
#include "PEView.h"
#include "PeEdit.h"
#include "resource.h"
#include <TlHelp32.h> 
#include <CommCtrl.h>
#include <commdlg.h>
#pragma comment(lib, "comctl32.lib")


//��������Ϣ����
//���̱���
VOID EnumProcess(HWND hListProcess);
//ģ�����
VOID EnumModules(HWND hListProcess, WPARAM wParam, LPARAM lParam, HWND hListModule);
//��ʼ��ProcessList
VOID InitProcessListView(HWND hListModule);
//��ʼ��ModuleList
VOID InitModuleListView(HWND hListModule);



//PE�鿴������Ϣ����
//PE�鿴���ڳ�ʼ��
BOOL InitPeView(HWND hPeViewDlg);
//PE�鿴���ڹر�
BOOL ClosePeView();
//PE�鿴֮�鿴�ڱ��ʼ��
VOID InitPeViewSection(HWND hListSection);
//�����ڱ���ʾ����Ϣ
VOID EnumSection(HWND hListSection);
//PE�鿴֮Ŀ¼��ʼ��
VOID InitPeViewDirectory(HWND hPeDirectoryViewDlg);
//�鿴�����
VOID InitPeViewImport(HWND hPeDirectoryImportDlg, HWND hListDLLName, HWND hListDLLInfo);
//������������������
VOID EnumImportFunc(HWND hListDLLName, WPARAM wParam, LPARAM lParam, HWND hListDLLInfo);

//�ӿ�
BOOL Shelling(HWND hShellDlg);


