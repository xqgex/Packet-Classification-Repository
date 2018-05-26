// HSM.cpp	algorithm for Packet Classification
// Version		0.99
// Auther		Xubo
// Copyright    Network Security Lab, RIIT, Tsinghua University, Beijing, China

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <windows.h>
#include "HSM.h"

// *** function for reading ip range , called by ReadFilter ***
// call form: ReadIPRange(fp,tempfilt->IPrange)
// fp: pointer to Filters File
// return: void
void ReadIPRange(FILE *fp,unsigned int* IPrange)
{
	/*assumes IPv4 prefixes*/
	// temporary variables to store IP range 
	unsigned int trange[4];	
	unsigned int mask;
	char validslash;
	// read IP range described by IP/mask
	//fscanf(fp, "%d.%d.%d.%d/%d", &trange[0],&trange[1],&trange[2],&trange[3],&mask);
	fscanf(fp, "%d.%d.%d.%d", &trange[0],&trange[1],&trange[2],&trange[3]);
	fscanf(fp, "%c", &validslash);

	// deal with default mask
	if(validslash != '/')
		mask = 32;
	else
		fscanf(fp,"%d", &mask);

	int masklit1;
	unsigned int masklit2,masklit3;
	mask = 32 - mask;
	masklit1 = mask / 8;
	masklit2 = mask % 8;
	
	unsigned int ptrange[4];
	int i;
	for(i=0;i<4;i++)
		ptrange[i] = trange[i];

	// count the start IP 
	for(i=3;i>3-masklit1;i--)
		ptrange[i] = 0;
	if(masklit2 != 0){
		masklit3 = 1;
		masklit3 <<= masklit2;
		masklit3 -= 1;
		masklit3 = ~masklit3;
		ptrange[3-masklit1] &= masklit3;
	}
	// store start IP 
	IPrange[0] = ptrange[0];
	IPrange[0] <<= 8;
	IPrange[0] += ptrange[1];
	IPrange[0] <<= 8;
	IPrange[0] += ptrange[2];
	IPrange[0] <<= 8;
	IPrange[0] += ptrange[3];
	
	// count the end IP
	for(i=3;i>3-masklit1;i--)
		ptrange[i] = 255;
	if(masklit2 != 0){
		masklit3 = 1;
		masklit3 <<= masklit2;
		masklit3 -= 1;
		ptrange[3-masklit1] |= masklit3;
	}
	// store end IP
	IPrange[1] = ptrange[0];
	IPrange[1] <<= 8;
	IPrange[1] += ptrange[1];
	IPrange[1] <<= 8;
	IPrange[1] += ptrange[2];
	IPrange[1] <<= 8;
	IPrange[1] += ptrange[3];
}

// Read port, called by ReadFilter
// fp: pointer to filter set file
// from:to	=>	0:65535 : specify the port range
// return: void
void ReadPort(FILE *fp, unsigned int *from, unsigned int *to)
{
	unsigned int tfrom;
	unsigned int tto;
	
	fscanf(fp,"%d : %d",&tfrom, &tto);
	
	*from = tfrom;
	*to = tto;
}


// ***	function for loading filters   ***
// fp:		file pointer to filterset file
// filtset: pointer to filterset, global variable
// cost:	the cost(position) of the current filter
// return:	0, this value can be an error code...
int ReadFilter(FILE *fp, FILTSET * filtset,	unsigned int cost)
{
	/*allocate a few more bytes just to be on the safe side to avoid overflow etc*/
	char validfilter;// validfilter means an '@'
	struct FILTER *tempfilt,tempfilt1;
//	unsigned int tact;
	
	//printf("Enter ReadFilter\n");
	while (!feof(fp))
	{
		fscanf(fp,"%c",&validfilter);
		if (validfilter != '@') continue;		// each rule should begin with an '@' 

		tempfilt = &tempfilt1;
		ReadIPRange(fp,tempfilt->dim[0]);					// reading SIP range
		ReadIPRange(fp,tempfilt->dim[1]);					// reading DIP range

		ReadPort(fp,&(tempfilt->dim[2][0]),&(tempfilt->dim[2][1]));
		ReadPort(fp,&(tempfilt->dim[3][0]),&(tempfilt->dim[3][1]));

		// read action taken by this rule
//		fscanf(fp, "%d", &tact);		// ReadAction
//		tempfilt->act = (unsigned char) tact;

		// read the cost (position) , which is specified by the last parameter of this function
		tempfilt->cost = cost;
		
		// copy the temp filter to the global one
		memcpy(&(filtset->filtArr[filtset->numFilters]),tempfilt,sizeof(struct FILTER));
		
		filtset->numFilters++;	   
		return SUCCESS;
	}

	return FALSE;
}

// ***	function for loading filters   ***
// fp:		file pointer to filterset file
// filtset: pointer to filterset, global variable
// return:	void
void LoadFilters(FILE *fp, FILTSET * filtset)
{

	filtset->numFilters = 0;	// initial filter number
	printf("Reading filters...\n\n");
	int line = 0;	// the line to read, indeed, this is the cost(position) of the filter to read
	while(!feof(fp)) 
	{
		ReadFilter(fp,filtset,line);
		line++;
	}
}

// Load packages
void LoadPackages(FILE *fp, PACKAGESET * packageset)
{
	packageset->numPackages = 0;	// initial package number
	int line = 0;					// the line to load
	char validfilter;				// validfilter means an '@'
	struct PACKAGE *temppack,temppack1;
	temppack = &temppack1;
	unsigned int tSIPseg[4],tDIPseg[4];
	while (!feof(fp))
	{
		fscanf(fp,"%c",&validfilter);
		if (validfilter != '@') continue;	// each rule should begin with an '@' 
		
		fscanf(fp,"%d.%d.%d.%d", &tSIPseg[0],&tSIPseg[1],&tSIPseg[2],&tSIPseg[3]);
		fscanf(fp,"%d.%d.%d.%d", &tDIPseg[0],&tDIPseg[1],&tDIPseg[2],&tDIPseg[3]);
		fscanf(fp,"%d", &temppack->sPort);
		fscanf(fp,"%d", &temppack->dPort);

		temppack->SIP = tSIPseg[0];
		temppack->SIP <<= 8;
		temppack->SIP += tSIPseg[1];
		temppack->SIP <<= 8;
		temppack->SIP += tSIPseg[2];
		temppack->SIP <<= 8;
		temppack->SIP += tSIPseg[3];
		temppack->DIP = tDIPseg[0];
		temppack->DIP <<= 8;
		temppack->DIP += tDIPseg[1];
		temppack->DIP <<= 8;
		temppack->DIP += tDIPseg[2];
		temppack->DIP <<= 8;
		temppack->DIP += tDIPseg[3];

		// dealing with dim[4]
		temppack->dim[0] = temppack->SIP;
		temppack->dim[1] = temppack->DIP;
		temppack->dim[2] = temppack->sPort;
		temppack->dim[3] = temppack->dPort;

		// copy the temp filter to the global one
		memcpy(&(packageset->PackArr[line]),temppack,sizeof(struct PACKAGE));
		line++;
		packageset->numPackages++;
	}	
}

// Load Filters from file, called by main
// return: void
void ReadFilterFile()
{
	FILE *fp;	// filter set file pointer
	char filename[] = "set0.txt";
	fp = fopen(filename,"r");
	if (fp == NULL) 
	{
		printf("Couldnt open filter set file \n");
		exit (0);
	}
	printf("filter file loaded: %s\n\n",filename);


	LoadFilters(fp, &filtset);	// loading filters...
	fclose(fp);
	printf("Filters Read: %d\n",filtset.numFilters);

	// check whether bmp[SIZE] is long enough to provide one bit for each rule
	if (LENGTH*SIZE < filtset.numFilters){
		printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\nThe cbm[SIZE] is not long enougth, please set SIZE higher!!!\n");
		exit(0);
	}

}


// Read filtset dimension range into dynamic array, called by main
void CreatePointArray()
{
	// Allocate memory spaces
	for(int i=0;i<4;i++)
		ptrfiltsetdim[i] = (ptrPoint) malloc (2 * filtset.numFilters * sizeof(TPOINT));
	
	// Read points to Arrays
	for(i=0;i<4;i++){
		for(unsigned int j=0;j<filtset.numFilters;j++){
			(ptrfiltsetdim[i]+2*j)->value = filtset.filtArr[j].dim[i][0];
			(ptrfiltsetdim[i]+2*j)->flag = 1;
			(ptrfiltsetdim[i]+2*j+1)->value = filtset.filtArr[j].dim[i][1];
			(ptrfiltsetdim[i]+2*j+1)->flag = 2;
		}
	}

	// Sort the points
	for(i=0;i<4;i++)
		SortPoints(ptrfiltsetdim[i],2*filtset.numFilters);

	// notify rate of progress
	printf("PointArray created!\n");
}


// Sort points by value, called by CreatePointArray
// when value is equal, make sure point whose flag equals 1 ranks in advance 
void SortPoints(ptrPoint pPoint, unsigned int num)
{
	unsigned int i,j,k;
	TPOINT tPoint;
	for(i=0;i<num-1;i++){
		k = i;
		for(j=i+1;j<num;j++){
			if( (pPoint+j)->value < (pPoint+k)->value )
				k = j;
			else if( ((pPoint+j)->value == (pPoint+k)->value) && ((pPoint+j)->flag < (pPoint+k)->flag) )
				k = j;
		}
		tPoint.value = (pPoint+i)->value;
		tPoint.flag = (pPoint+i)->flag;
		(pPoint+i)->value = (pPoint+k)->value;
		(pPoint+i)->flag = (pPoint+k)->flag;
		(pPoint+k)->value = tPoint.value;
		(pPoint+k)->flag = tPoint.flag;
	}
}

// set the bit referring to a rule	( 0 or 1 )
// call form : SetBmpBit(bmp,i,TRUE)
void SetBmpBit(unsigned int *tbmp,unsigned int i, bool value)
{
	unsigned int k,pos;
	k = SIZE-1 - (i/LENGTH);
	pos = i % LENGTH;
	unsigned int tempInt = 1;
	tempInt <<= pos;
	if (value == TRUE)
		tbmp[k] |= tempInt;
	else{
		tempInt = ~tempInt;
		tbmp[k] &= tempInt;
	}
}

// Create dimension fragmentation array used for lookup, called by main
void CreateFragArray()
{
	ptrFragLinklist ptrfraglinklist[4];
	unsigned int k;
	struct FRAGNODE *tfrag,*tprefrag;
////////////////////////////////////////////////////////////////////////////////////////
	// Create fraglinklist firstly
	for(int i=0;i<4;i++){
		ptrfraglinklist[i] = (ptrFragLinklist) malloc (sizeof(FRAGLINKLIST));
		ptrfraglinklist[i]->fragNum = 0;
		ptrfraglinklist[i]->head = (struct FRAGNODE *) malloc (sizeof(struct FRAGNODE));

		// set first frag start point
		ptrfraglinklist[i]->head->start = ptrfiltsetdim[i]->value;
		ptrfraglinklist[i]->head->next = NULL;

		// searching for first frag end point
		for(k=1;k<2*filtset.numFilters;k++){
			// when frag end point is rule end point
			if( ((2 == (ptrfiltsetdim[i]+k)->flag)) && \
				((ptrfiltsetdim[i]+k)->value >= ptrfraglinklist[i]->head->start) ){
				ptrfraglinklist[i]->head->end = (ptrfiltsetdim[i]+k)->value;
				ptrfraglinklist[i]->fragNum ++;
				break;
			}
			// when frag end point is rule start point
			else if( (ptrfiltsetdim[i]+k)->value > ptrfraglinklist[i]->head->start ){
				ptrfraglinklist[i]->head->end = (ptrfiltsetdim[i]+k)->value - 1;
				ptrfraglinklist[i]->fragNum ++;
				break;
			}
		}
		tprefrag = ptrfraglinklist[i]->head;

		// create fraglinklist
		while( (k<2*filtset.numFilters-1) && (tprefrag->end + 1 != 0) ){
			tfrag = (struct FRAGNODE *) malloc (sizeof(struct FRAGNODE));
			// set new start point
			tfrag->start = tprefrag->end + 1;
			tfrag->next = NULL;
			
			// searching for end point
			for(k=k+1;k<2*filtset.numFilters;k++){
				// when frag end point is rule end point
				if( ((2 == (ptrfiltsetdim[i]+k)->flag)) && \
					((ptrfiltsetdim[i]+k)->value >= tfrag->start) ){
					tfrag->end = (ptrfiltsetdim[i]+k)->value;
					ptrfraglinklist[i]->fragNum ++;
					break;
				}
				// when frag end point is rule start point
				else if( (ptrfiltsetdim[i]+k)->value > tfrag->start ){
					tfrag->end = (ptrfiltsetdim[i]+k)->value - 1;
					ptrfraglinklist[i]->fragNum ++;
					break;
				}
			}
			tprefrag->next = tfrag;
			tprefrag = tfrag;
		}
		// use for debug
		printf("fragNum of fraglinklist[%d] is: %d\n",i,ptrfraglinklist[i]->fragNum);
	}

	// Release ptrfiltsetdim[4]
	for(i=0;i<4;i++)
		free(ptrfiltsetdim[i]);
////////////////////////////////////////////////////////////////////////////////////////
	// Create frag array
	for(i=0;i<4;i++){
		fragNum[i] = ptrfraglinklist[i]->fragNum;
		ptrTfrag[i] = (ptrTFrag) malloc (fragNum[i] * sizeof(struct TFRAG));
		
		// fill the frag arrays
		tfrag = ptrfraglinklist[i]->head;
		for(unsigned int j=0;j<fragNum[i];j++){
			(ptrTfrag[i]+j)->start = tfrag->start;
			(ptrTfrag[i]+j)->end = tfrag->end;
			
			// initialize frag cbm
			for(int m=0;m<SIZE;m++)
				(ptrTfrag[i]+j)->cbm[m] = 0;
			
			// set the cbm according to the rules containing the frag
			for(unsigned int r=0;r<filtset.numFilters;r++){
				if( ( (ptrTfrag[i]+j)->start >= filtset.filtArr[r].dim[i][0]) && \
					( (ptrTfrag[i]+j)->end <= filtset.filtArr[r].dim[i][1] ) ){
					
					SetBmpBit((ptrTfrag[i]+j)->cbm,r,TRUE);
				}
			}
			// next frag
			tfrag = tfrag->next;
		}
	}

	// notify rate of progress
	printf("ptrTfrag[4] created!\n");
	
	// release ptrfraglinklist
	for(i=0;i<4;i++){
		tprefrag = ptrfraglinklist[i]->head;
		for(unsigned int j=0;j<ptrfraglinklist[i]->fragNum;j++){
			tfrag = tprefrag->next;
			free(tprefrag);
			tprefrag = tfrag;
		}
		free(ptrfraglinklist[i]);
	}
	
	// notify rate of progress
	printf("FragArray created!\n");
}

// Compare two bmp, called by SearchBmp
// return: same -- TRUE ;  different -- FALSE
bool CompareBmp(unsigned int *abmp, unsigned int *bbmp)
{
	if( (abmp == NULL) || (bbmp == NULL) )
		return FALSE;

	for(int i=0;i<SIZE;i++)
		if( (*(abmp+i)) != (*(bbmp+i)) )
			return FALSE;

	return TRUE;
}


// Initialize listEqs, called by CreateMapTable
// call form : InitListEqs(listEqs[i])
void InitListEqs(LISTEqS *ptrlistEqs)
{
	ptrlistEqs->nCES = 0;
	ptrlistEqs->head = NULL;
	ptrlistEqs->rear = NULL;
}

// Function to search bmp in listEqs, called by CreateMapTable
// call form : SearchBmp(listEqs[i],bmp)
// Return: if tbmp not exist in listEqs, return -1
// else return eqID of CES whose cbm matches tbmp
int SearchBmp(LISTEqS *ptrlistEqs,unsigned int *tbmp)
{
	CES *tCES;
	tCES = ptrlistEqs->head;
	for(unsigned int i=0;i<ptrlistEqs->nCES;i++){
		if(CompareBmp(tCES->cbm,tbmp))
			return i;
		else
			tCES = tCES->next;
	}
	return -1;
}

// Add new CES to ListEqs, called by CreateMapTable
// call form : AddListEqsCES(listEqs[i],bmp)
// Return : the eqID of the new CES
int AddListEqsCES(LISTEqS *ptrlistEqs,unsigned int *tbmp)
{
	CES *tCES;
	tCES = (CES *) malloc (sizeof(CES));
	if(ptrlistEqs->head == NULL){

		// new CES
		tCES->eqID = 0;
		tCES->next = NULL;
		for(int i=0;i<SIZE;i++)
			tCES->cbm[i] = tbmp[i];

		// add new CES to tlistEqs
		ptrlistEqs->nCES = 1;
		ptrlistEqs->head = tCES;
		ptrlistEqs->rear = tCES;
	}
	else{
		// new CES
		tCES->eqID = ptrlistEqs->nCES;
		tCES->next = NULL;
		for(int i=0;i<SIZE;i++)
			tCES->cbm[i] = tbmp[i];

		// add new CES to tlistEqs
		ptrlistEqs->nCES++;
		ptrlistEqs->rear->next = tCES;
		ptrlistEqs->rear = tCES;
	}
	return ptrlistEqs->rear->eqID;
}

// Find order of ptrfrag[4] by size
void FindOrder()
{
	int temp;
	// initialize dot[4]
	for(int i=0;i<4;i++)
		dot[i] = i;
	
	// find order by size
	for(i=0;i<3;i++){
		for(int j=i+1;j<4;j++){
			if(fragNum[dot[j]] < fragNum[dot[i]]){
				temp = dot[i];
				dot[i] = dot[j];
				dot[j] = temp;
			}
		}
	}
}


// Create AMT & PMT, called by main
void CreateMapTable()
{
	unsigned int intersectedBmp[SIZE];
	int tempeqID;
	FindOrder();
	for(int fid=0;fid<2;fid++){
		MT[fid] = (unsigned int *) malloc (fragNum[dot[fid]] * fragNum[dot[3-fid]] * sizeof(unsigned int));
		listEqs[fid] = (ptrLISTEqS) malloc (sizeof(struct LISTEqS));
		
		// initialize listEqs[2]
		InitListEqs(listEqs[fid]);

		for(unsigned int i=0;i<fragNum[dot[fid]];i++){
			for(unsigned int j=0;j<fragNum[dot[3-fid]];j++){

				// generate intersectedBmp
				for(int m=0;m<SIZE;m++)
					intersectedBmp[m] = (ptrTfrag[dot[fid]]+i)->cbm[m] & (ptrTfrag[dot[3-fid]]+j)->cbm[m];
				
				// search listEqs[fid] for intersectedBmp
				tempeqID = SearchBmp(listEqs[fid],intersectedBmp);

				// Not exist, add intersectedBmp to listEqs
				if (-1 == tempeqID)
					tempeqID = AddListEqsCES(listEqs[fid],intersectedBmp);

				// Set MT[fid]
				*(MT[fid]+i*fragNum[dot[3-fid]]+j) = tempeqID;
			}
		}

	}
	// notify rate of progress
	printf("AMT & PMT created!\n");

	// Creating ptrfrag[4]
	for(unsigned int i=0;i<4;i++){
		ptrfrag[i] = (ptrFrag) malloc (fragNum[i] * sizeof(struct FRAG));
		for(unsigned int j=0;j<fragNum[i];j++){
			(ptrfrag[i]+j)->start = (ptrTfrag[i]+j)->start;
			(ptrfrag[i]+j)->end = (ptrTfrag[i]+j)->end;
		}
	}
	// notify rate of progress
	printf("ptrfrag[4] created!\n");
	
	// Release ptrTfrag[4]
	for(i=0;i<4;i++)
		free(ptrTfrag[i]);
	
	// notify rate of progress
	printf("ptrTfrag[4] released!\n");
}

// Get rule cost number with highest priority, called by CreatePLT
// Note : used for packet matching more than 1 rules
// call form : cost = GetRuleCost(endBmp)
// return : cost number with highest priority
unsigned int GetRuleCost(unsigned int *tbmp)
{
	unsigned int tempInt;
	unsigned int tempValue;
	for(int k=SIZE-1;k>=0;k--){

		tempInt = 1;
		for(int pos=1;pos<=LENGTH;pos++){
			
			tempValue = tbmp[k] & tempInt;
			if( tempValue )
				return ( LENGTH*(SIZE-1-k) + pos );
			tempInt <<= 1;
		}
	}
//	printf("!!! Lack of default rule!\nThere is no rule matched!\n");
//	return -1;
	return filtset.numFilters;
}

// Locate CES by eqID in listEqs
CES *LocateCES(ptrLISTEqS listEqs,unsigned short ID)
{
	CES *tCES;
	tCES = listEqs->head;
	for(unsigned short i=0;i<ID;i++)
		tCES = tCES->next;
	return tCES;
}

// Free listEqs, called by CreatePLT
void FreeListEqs(LISTEqS *ptrlistEqs)
{
	if(ptrlistEqs->head == NULL)
		return;

	CES *tCES;
	for(unsigned int i=0;i<ptrlistEqs->nCES;i++){

		tCES = ptrlistEqs->head;
		ptrlistEqs->head = ptrlistEqs->head->next;
		free(tCES);
	}
	ptrlistEqs->rear = NULL;	
}

// Create PLT, called by main
void CreatePLT()
{
	PLT = (unsigned int *) malloc ( listEqs[0]->nCES * listEqs[1]->nCES * sizeof(unsigned int));
	
	// fill in PLT
	CES *tCES[2];
	unsigned int tcbm[SIZE];
	for(unsigned short i=0;i<listEqs[0]->nCES;i++){
		for(unsigned short j=0;j<listEqs[1]->nCES;j++){

			tCES[0] = LocateCES(listEqs[0],i);
			tCES[1] = LocateCES(listEqs[1],j);
			
			// generate tcbm
			for(int m=0;m<SIZE;m++)
				tcbm[m] = tCES[0]->cbm[m] & tCES[1]->cbm[m];
			
			// fill PLT with highest priority rule
			PLT[i * listEqs[1]->nCES + j] = GetRuleCost(tcbm);
		}
	}

	// release listEqs[2]
	for(i=0;i<2;i++)
		FreeListEqs(listEqs[i]);
	
	// notify rate of progress
	printf("PLT created!\n");
}

// Lookup, called by main
void Lookup()
{
	// notify rate of progress
	printf("Start lookup...\n");
	
	// Read packages from file packageset.txt
	FILE *fp;						
	char filename[] = "packageset.txt";
	fp = fopen(filename,"r");
	if (fp == NULL) 
	{
		printf("Cannot open package set file \n");
		exit (0);
	}
	LoadPackages(fp, &packageset);	// loading packages...
	fclose(fp);	

	int lookuptime = GetTickCount();
	// Lookup Progress
	unsigned int *lookupResult;
	lookupResult = (unsigned int *) malloc (packageset.numPackages * sizeof(unsigned int));
	
	// lookup segment id
	unsigned int segID[4],AMTid,PMTid;
	for(unsigned int j=0;j<packageset.numPackages;j++){
		for(int i=0;i<4;i++){
			segID[i] = SearchSegID(ptrfrag[i],fragNum[i],packageset.PackArr[j].dim[i]);
		}
		AMTid = *(MT[0] + segID[dot[0]] * fragNum[dot[3]] + segID[dot[3]]);
		PMTid = *(MT[1] + segID[dot[1]] * fragNum[dot[2]] + segID[dot[2]]);
		lookupResult[j] = *(PLT + AMTid * listEqs[1]->nCES + PMTid);
	}
	lookuptime = GetTickCount() - lookuptime;
	printf("Lookup finished!\n");
	printf("Time for lookup is %d ms\n",lookuptime);

	// store lookupResult int lookupResult.txt
	char filename1[] = "lookupResult.txt";
	fp = fopen(filename1,"w+");
	if (fp == NULL) 
	{
		printf("Cannot open lookupResult file \n");
		exit (0);
	}
	for(unsigned int i=0;i<packageset.numPackages;i++){
		fprintf(fp,"%d\n",lookupResult[i]);
	}
	fclose(fp);	
}

// Search segment id, called by Lookup
// use binsearch
unsigned int SearchSegID(ptrFrag pfrag,unsigned int tfragNum,unsigned int value)
{
	unsigned int low,mid,high;
	low = 0;
	high = tfragNum - 1;
	while(low <= high){
		mid = (low + high)/2;
		if( ( (pfrag+mid)->start <= value) && ((pfrag+mid)->end >= value) )
			return mid;
		if( (pfrag+mid)->start > value )
			high = mid - 1;
		else
			low = mid + 1;
	}
	printf("!!!Lack of default rule!!!\n");
	return -1;
}

// Count memory used 
void CountMemory()
{
	unsigned int memused,fragmem,MTmem,PLTmem;

	// ptrFrag[4]
	unsigned int num = 0;
	for(int i=0;i<4;i++)
		num += fragNum[i];
	fragmem = num * 2 * sizeof(unsigned int);

	// fragNum[4]
	fragmem += 4 * sizeof(unsigned int);

	//MT[2]
	num = fragNum[dot[0]] * fragNum[dot[3]] + fragNum[dot[1]] * fragNum[dot[2]];
	MTmem = num * sizeof(unsigned int);

	//PLT
	num = listEqs[0]->nCES * listEqs[1]->nCES;
	PLTmem = num * sizeof(unsigned int);

	memused = fragmem + MTmem + PLTmem;
	printf("Memory used:%d\n",memused);
	
	// store memory used int memoryused.txt
	FILE *fp;
	char filename[] = "memoryused.txt";
	fp = fopen(filename,"w+");
	if (fp == NULL) 
	{
		printf("Cannot open memoryused file \n");
		exit (0);
	}
	fprintf(fp,"Total memory used:\t%d bytes\n",memused);
	fprintf(fp,"Memory used by ptrFrag:\t%d bytes\n",fragmem);
	for(i=0;i<4;i++)
		fprintf(fp,"fragNum[%d] is: %d\n",i,fragNum[i]);
	fprintf(fp,"Memory used by MTmem:\t%d bytes\n",MTmem);
	fprintf(fp,"Memory used bu PLTmem:\t%d bytes\n",PLTmem);
	fclose(fp);
}

int main(int argc, char* argv[])
{
// reading data 
	ReadFilterFile();

// check the result of the loaded filters
//	CheckData();

	int time;
	time = GetTickCount();
// Read filtset dimension range into dynamic array
	CreatePointArray();

// Create dimension fragmentation array used for lookup	
	CreateFragArray();

// Create AMT & PMT
	CreateMapTable();

// Create PLT
	CreatePLT();

	time = GetTickCount() - time;
	printf("Time used for preprocessing is %d ms\n",time);
// CountMemory
	CountMemory();
	
	
// Lookup
	Lookup();
	
	return 0;
}