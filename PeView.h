#pragma once
#include<Windows.h>
#include <stdio.h>
#include <stdlib.h>
class PeView
{
public:
	//文件镜像（文件对齐）
	LPVOID fileBuffer = NULL;
	DWORD fileBufferSize = 0;

	//PE头的数据结构
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//导出表（序号0）
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	//导入表（序号1）
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	//重定位表（序号5）
	PIMAGE_BASE_RELOCATION pBaseRelocation = NULL;
	//绑定导入表（序号11）
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDescriptor = NULL;

private:
	//读取文件																							
	DWORD ReadPEFile(IN LPSTR lpszFile);
public:
	//获取PE头
	BOOL LoadPEHeader(LPVOID fileBuffer);
	//对齐计算,返回对齐后的数值
	DWORD AlignCalc(IN DWORD data, IN DWORD alignSize);
	//将内存偏移转换为文件偏移																														
	DWORD RvaToFoaNoBase(IN DWORD dwRva);
	//将内存偏移转换为文件偏移																														
	DWORD RvaToFoa(IN DWORD dwRva);
	//根据文件名构造
	PeView(IN LPSTR lpszFile);
	//析构函数
	virtual ~PeView();
};