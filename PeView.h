#pragma once
#include<Windows.h>
#include <stdio.h>
#include <stdlib.h>
class PeView
{
public:
	//�ļ������ļ����룩
	LPVOID fileBuffer = NULL;
	DWORD fileBufferSize = 0;

	//PEͷ�����ݽṹ
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//���������0��
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	//��������1��
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	//�ض�λ�����5��
	PIMAGE_BASE_RELOCATION pBaseRelocation = NULL;
	//�󶨵�������11��
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDescriptor = NULL;

private:
	//��ȡ�ļ�																							
	DWORD ReadPEFile(IN LPSTR lpszFile);
public:
	//��ȡPEͷ
	BOOL LoadPEHeader(LPVOID fileBuffer);
	//�������,���ض�������ֵ
	DWORD AlignCalc(IN DWORD data, IN DWORD alignSize);
	//���ڴ�ƫ��ת��Ϊ�ļ�ƫ��																														
	DWORD RvaToFoaNoBase(IN DWORD dwRva);
	//���ڴ�ƫ��ת��Ϊ�ļ�ƫ��																														
	DWORD RvaToFoa(IN DWORD dwRva);
	//�����ļ�������
	PeView(IN LPSTR lpszFile);
	//��������
	virtual ~PeView();
};