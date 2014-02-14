/* itmaker.h --

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
   <ashkbiz@yahoo.com>>
*/
#pragma once
#include <list>

#define IMPORT_TABLE_EXE		0
#define IMPORT_TABLE_OCX		1
//----------------------------------------------------------------
class CITMaker
{
private:
	//----------------------------------------
	DWORD Get_IT_Size();
	void Initialization(int iType);
	//----------------------------------------
protected:
	//----------------------------------------
public:
	//----------------------------------------
	DWORD dwSize;
	PCHAR pMem;
	//----------------------------------------
	CITMaker(int iType);
	~CITMaker();
	void Build(DWORD dwRVA);
	//----------------------------------------
};
//----------------------------------------------------------------