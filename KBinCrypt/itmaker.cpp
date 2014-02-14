/* itmaker.cpp --

   This file is part of the "PE Maker".

   Copyright (C) 2005-2006 Ashkbiz Danehkar
   All Rights Reserved.

   "PE Maker" library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYRIGHT.TXT.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   NTCore's site:
   http://www.ntcore.com/

   yodap's Site:
   http://yodap.sourceforge.net

   Ashkbiz Danehkar
   <ashkbiz@yahoo.com>
*/

#include <winnt.h>
#include <imagehlp.h>
#include "itmaker.h"

#ifdef _DEBUG
#define DEBUG_NEW
#endif

//IMAGE_IMPORT_DESCRIPTOR
//IMAGE_THUNK_DATA
//----------------------------------------------------------------
static const char *sz_IT_EXE_strings[]=
{
	"Kernel32.dll",
	"LoadLibraryA",
	"GetProcAddress",
	0,
	"User32.dll",
	"MessageBoxA",
	"DispatchMessageA",
	"CreateWindowExA",
	0,
	"Oleaut32.dll",
	"CreateErrorInfo",
	"SafeArrayPtrOfIndex",
	0,
	"ComCtl32.dll",
	"InitCommonControlsEx",
	"ImageList_SetIconSize",
	0,
	0,
};

const char *sz_IT_OCX_strings[]=
{
	"Kernel32.dll",
	"LoadLibraryA",
	"GetProcAddress",
	"GetModuleHandleA",
	0,
	"User32.dll",
	"GetKeyboardType",
	"WindowFromPoint",
	0,
	"AdvApi32.dll",
	"RegQueryValueExA",
	"RegSetValueExA",
	"StartServiceA",
	0,
	"Oleaut32.dll",
	"SysFreeString",
	"CreateErrorInfo",
	"SafeArrayPtrOfIndex",
	0,
	"Gdi32.dll",
	"UnrealizeObject",
	0,
	"Ole32.dll",
	"CreateStreamOnHGlobal",
	"IsEqualGUID",
	0,
	"ComCtl32.dll",
	"ImageList_SetIconSize",
	0,
	0,
};
//----------------------------------------------------------------
using namespace std;

//----------------------------------------------------------------
typedef struct
{
	CHAR szFunction[32];
}t_IMAGE_THUNK, *pt_IMAGE_THUNK;
//----------------------------------------------------------------
typedef struct
{
	CHAR szLibrary[32];
	list <t_IMAGE_THUNK> ThunksList;
	list <t_IMAGE_THUNK>::iterator ThunkIter;
	CHAR szFunction[32];
}t_IMAGE_IMPORT_TABLE, *pt_IMAGE_IMPORT_TABLE;
//----------------------------------------------------------------
static list <t_IMAGE_IMPORT_TABLE> ImportTable;
static list <t_IMAGE_IMPORT_TABLE>::iterator ImportIter;
//================================================================
CITMaker::CITMaker(int iType)
{
	Initialization(iType);
	dwSize=Get_IT_Size();
	pMem=new CHAR[dwSize];
}

CITMaker::~CITMaker()
{
	ImportTable.clear();
	delete [] pMem;
}
//----------------------------------------------------------------
// This function makes the dll name strings, saves them to the linked list 
void CITMaker::Initialization(int iType)
{
	int i;
	PCHAR *sz_IT_strings;
	t_IMAGE_IMPORT_TABLE	imageimport;
	t_IMAGE_THUNK			imagethunk;
	switch(iType)
	{
	case IMPORT_TABLE_EXE:
		sz_IT_strings=(PCHAR *)sz_IT_EXE_strings;
		break;
	case IMPORT_TABLE_OCX:
		sz_IT_strings=(PCHAR *)sz_IT_OCX_strings;
		break;
	}
	//--------------------------------------------
	ImportTable.clear();
	i=0;
	do
	{
		strcpy(imageimport.szLibrary,sz_IT_strings[i]);
		imageimport.ThunksList.clear();
		do
		{
			i++;
			if(sz_IT_strings[i]!=0)
			{	
				strcpy(imagethunk.szFunction,sz_IT_strings[i]);
				imageimport.ThunksList.push_back(imagethunk);
			}
		}while(sz_IT_strings[i]!=0);
		ImportTable.push_back(imageimport);	
		i++;
	}
	while(sz_IT_strings[i]!=0);
	//--------------------------------------------
}
//----------------------------------------------------------------
// This function calculated zise of Import Table.
DWORD CITMaker::Get_IT_Size()
{
	DWORD dwDLLNum=0;
	DWORD dwFunNum=0;
	DWORD dwszDLLSize=0;
	DWORD dwszFuncSize=0;
	DWORD dwImportSize=0;
	t_IMAGE_IMPORT_TABLE	imageimport;
	t_IMAGE_THUNK			imagethunk;
	for(ImportIter=ImportTable.begin();ImportIter!=ImportTable.end();ImportIter++)
	{
		imageimport=*ImportIter;
		dwszDLLSize=dwszDLLSize+strlen(imageimport.szLibrary)+1;
		for(imageimport.ThunkIter=imageimport.ThunksList.begin();
			imageimport.ThunkIter!=imageimport.ThunksList.end();
			imageimport.ThunkIter++)
		{
			imagethunk=*imageimport.ThunkIter;
			dwszFuncSize=dwszFuncSize+2+strlen(imagethunk.szFunction)+1;
			dwFunNum++;
		}
		dwFunNum++;
		dwDLLNum++;
	}
	dwDLLNum++;
	dwImportSize=dwDLLNum*20+dwFunNum*4+dwszDLLSize+dwszFuncSize;
	return(dwImportSize);
}
//----------------------------------------------------------------
//----------------------------------------------------------------
// This function build the dll name strings, saves the ImageImportDescriptors to the loader data.
void CITMaker::Build(DWORD dwRVA)
{
	DWORD					pITBaseRVA=dwRVA;
	DWORD					temp;
	DWORD					dwDLLNum, dwDLLName, dwDLLFirst, dwszDLLSize;
	DWORD					dwIIDNum, dwFunNum, dwFunFirst, dwszFuncSize;
	DWORD					dwFirstThunk, dwImportSize;
	t_IMAGE_IMPORT_TABLE	imageimport;
	t_IMAGE_THUNK			imagethunk;
	IMAGE_IMPORT_DESCRIPTOR import_descriptor;// -> IID
	//--------------------------------------------
	import_descriptor.OriginalFirstThunk=0;
	import_descriptor.TimeDateStamp=0;
	import_descriptor.ForwarderChain=0;
	import_descriptor.Name=0;
	import_descriptor.FirstThunk=0;
	dwDLLNum=dwDLLName=dwDLLFirst=dwszDLLSize=0;
	dwIIDNum=dwFunNum=dwFunFirst=dwszFuncSize=0;
	dwFirstThunk=dwImportSize=0;
	//--------------------------------------------
	for(ImportIter=ImportTable.begin();ImportIter!=ImportTable.end();ImportIter++)
	{
		imageimport=*ImportIter;
		dwszDLLSize=dwszDLLSize+strlen(imageimport.szLibrary)+1;
		for(imageimport.ThunkIter=imageimport.ThunksList.begin();
			imageimport.ThunkIter!=imageimport.ThunksList.end();
			imageimport.ThunkIter++)
		{
			imagethunk=*imageimport.ThunkIter;
			dwszFuncSize=dwszFuncSize+2+strlen(imagethunk.szFunction)+1;
			dwFunNum++;
		}
		dwFunNum++;
		dwDLLNum++;
	}
	dwDLLNum++;
	dwImportSize=dwDLLNum*20+dwFunNum*4+dwszDLLSize+dwszFuncSize;
	//--------------------------------------------
	FillMemory(pMem,dwImportSize,0x00);
	dwFirstThunk=dwDLLNum*20;
	dwDLLFirst=dwDLLNum*20+dwFunNum*4;
	dwFunFirst=dwDLLNum*20+dwFunNum*4+dwszDLLSize;
	//pITBaseRVA
	//--------------------------------------------
	for(ImportIter=ImportTable.begin();ImportIter!=ImportTable.end();ImportIter++)
	{
		imageimport=*ImportIter;
		import_descriptor.Name=pITBaseRVA+dwDLLFirst;
		import_descriptor.FirstThunk=pITBaseRVA+dwFirstThunk;
		memcpy(pMem+dwIIDNum*sizeof(IMAGE_IMPORT_DESCRIPTOR),
				   &import_descriptor,
			       sizeof(IMAGE_IMPORT_DESCRIPTOR));
		memcpy(pMem+dwDLLFirst,
				   imageimport.szLibrary,
				   strlen(imageimport.szLibrary)+1);
		//--------------------------------------------
		for(imageimport.ThunkIter=imageimport.ThunksList.begin();
			imageimport.ThunkIter!=imageimport.ThunksList.end();
			imageimport.ThunkIter++)
		{
			imagethunk=*imageimport.ThunkIter;
			temp=pITBaseRVA+dwFunFirst;
			memcpy(pMem+dwFirstThunk,
					   &temp,
				       4);
			memcpy(pMem+dwFunFirst+2,
					   imagethunk.szFunction,
				       strlen(imagethunk.szFunction)+1);
			dwFunFirst=dwFunFirst+2+strlen(imagethunk.szFunction)+1;
			dwFirstThunk=dwFirstThunk+4;
		}
		//--------------------------------------------
		temp=0;
		memcpy(pMem+dwFirstThunk,
					   &temp,
				       4);
		dwFirstThunk=dwFirstThunk+4;
		dwDLLFirst=dwDLLFirst+strlen(imageimport.szLibrary)+1;
		dwIIDNum++;
	}
	//--------------------------------------------
	import_descriptor.Name=0;
	import_descriptor.FirstThunk=0;
	//--------------------------------------------
	memcpy(pMem+dwIIDNum*sizeof(IMAGE_IMPORT_DESCRIPTOR),
			   &import_descriptor,
			   sizeof(IMAGE_IMPORT_DESCRIPTOR));
}