#pragma once
#include "framework.h"
#include "PEView.h"
#include "PeEdit.h"
#include "resource.h"
#include <TlHelp32.h> 
#include <CommCtrl.h>
#include <commdlg.h>
#pragma comment(lib, "comctl32.lib")


//主窗口消息处理
//进程遍历
VOID EnumProcess(HWND hListProcess);
//模块遍历
VOID EnumModules(HWND hListProcess, WPARAM wParam, LPARAM lParam, HWND hListModule);
//初始化ProcessList
VOID InitProcessListView(HWND hListModule);
//初始化ModuleList
VOID InitModuleListView(HWND hListModule);



//PE查看窗口消息处理
//PE查看窗口初始化
BOOL InitPeView(HWND hPeViewDlg);
//PE查看窗口关闭
BOOL ClosePeView();
//PE查看之查看节表初始化
VOID InitPeViewSection(HWND hListSection);
//遍历节表显示节信息
VOID EnumSection(HWND hListSection);
//PE查看之目录初始化
VOID InitPeViewDirectory(HWND hPeDirectoryViewDlg);
//查看导入表
VOID InitPeViewImport(HWND hPeDirectoryImportDlg, HWND hListDLLName, HWND hListDLLInfo);
//遍历导入表函数名和序号
VOID EnumImportFunc(HWND hListDLLName, WPARAM wParam, LPARAM lParam, HWND hListDLLInfo);

//加壳
BOOL Shelling(HWND hShellDlg);


