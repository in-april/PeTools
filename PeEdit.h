#pragma once
#include "PEView.h"
class PeEdit:public PeView
{
public:
	//�ڴ澵���ڴ���룩
	LPVOID imageBuffer = NULL;
	DWORD imageBufferSize = 0;

	//�����ļ�������
	PeEdit(IN LPSTR lpszFile);
	//��������
	virtual ~PeEdit();
	//�ڴ����
	//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С																
	DWORD CopyFileBufferToImageBuffer();
	//�ļ�����															
	//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С																
	DWORD CopyImageBufferToFileBuffer();
	//�����ڣ�pImageBufferΪ�ڴ������ĵ�ַ
	//���������ڵ�ʵ�ʴ�С��
	DWORD AddSection(DWORD size);
	//���ڴ��е����ݴ洢���ļ�														
	//��ȡʧ�ܷ���0  ���򷵻�1																
	BOOL DumpFile(LPSTR lpszFile);
};

