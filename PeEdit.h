#pragma once
#include "PEView.h"
class PeEdit:public PeView
{
public:
	//内存镜像（内存对齐）
	LPVOID imageBuffer = NULL;
	DWORD imageBufferSize = 0;

	//根据文件名构造
	PeEdit(IN LPSTR lpszFile);
	//析构函数
	virtual ~PeEdit();
	//内存对齐
	//读取失败返回0  否则返回复制的大小																
	DWORD CopyFileBufferToImageBuffer();
	//文件对齐															
	//读取失败返回0  否则返回复制的大小																
	DWORD CopyImageBufferToFileBuffer();
	//新增节，pImageBuffer为内存拉伸后的地址
	//返回新增节的实际大小；
	DWORD AddSection(DWORD size);
	//将内存中的数据存储到文件														
	//读取失败返回0  否则返回1																
	BOOL DumpFile(LPSTR lpszFile);
};

