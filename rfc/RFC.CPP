// RFC.cpp	algorithm for Packet Classification
// Version		0.99
// Auther		Xubo

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <windows.h>
#include "RFC.h"

// *** function for reading ip range ***
// call form: ReadIPRange(fp,tempfilt->highSIPrange,tempfilt->lowSIPrange)
// fp: pointer to Filters File
// highSIPrange: pointer to the high SIP range in the FILTER structure
// lowSIPrange: pointer to the low SIP range in the FILTER structure
// return: void
void ReadIPRange(FILE *fp,unsigned int* highRange,unsigned int* lowRange)
{
	/*assumes IPv4 prefixes*/
	// temporary variables to store IP range 
	unsigned int trange[4];	
	unsigned int mask;
	char validslash;
	// read IP range described by IP/mask
//	fscanf(fp, "%d.%d.%d.%d/%d", &trange[0],&trange[1],&trange[2],&trange[3],&mask);
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
	highRange[0] = ptrange[0];
	highRange[0] <<= 8;
	highRange[0] += ptrange[1];
	lowRange[0] = ptrange[2];
	lowRange[0] <<= 8;
	lowRange[0] += ptrange[3];
	
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
	highRange[1] = ptrange[0];
	highRange[1] <<= 8;
	highRange[1] += ptrange[1];
	lowRange[1] = ptrange[2];
	lowRange[1] <<= 8;
	lowRange[1] += ptrange[3];
}


// Read protocol, called by ReadFilter
// fp: pointer to filter set file
// protocol: 17 for tcp
// return: void
void ReadProtocol(FILE *fp, unsigned char *from, unsigned char *to)
{
	unsigned int tfrom,tto;
	
    fscanf(fp, "%d:%d", &tfrom, &tto);
	*from = (unsigned char)tfrom;
	*to = (unsigned char) tto;
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
		if (validfilter != '@') continue;	// each rule should begin with an '@' 

		tempfilt = &tempfilt1;
		ReadIPRange(fp,tempfilt->dim[0],tempfilt->dim[1]);	// reading SIP range
		ReadIPRange(fp,tempfilt->dim[2],tempfilt->dim[3]);	// reading DIP range

		ReadPort(fp,&(tempfilt->dim[4][0]),&(tempfilt->dim[4][1]));
		ReadPort(fp,&(tempfilt->dim[5][0]),&(tempfilt->dim[5][1]));

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


// Load Package Set into memory
void LoadPackages(FILE *fp, PACKAGESET * packageset)
{
	packageset->numPackages = 0;	// initial package number
	int line = 0;					// the line to load
	char validfilter;				// validfilter means an '@'
	struct PACKAGE *temppack,temppack1;
	temppack = &temppack1;

	while (!feof(fp))
	{
		fscanf(fp,"%c",&validfilter);
		if (validfilter != '@') continue;	// each rule should begin with an '@' 
		
		fscanf(fp,"%d.%d.%d.%d", &temppack->highSIP[0],&temppack->highSIP[1],&temppack->lowSIP[0],&temppack->lowSIP[1]);
		fscanf(fp,"%d.%d.%d.%d", &temppack->highDIP[0],&temppack->highDIP[1],&temppack->lowDIP[0],&temppack->lowDIP[1]);
		fscanf(fp,"%d", &temppack->sPort);
		fscanf(fp,"%d", &temppack->dPort);

		// dealing with dim[6]
		temppack->dim[0] = temppack->highSIP[0];
		temppack->dim[0] <<= 8;
		temppack->dim[0] += temppack->highSIP[1];

		temppack->dim[1] = temppack->lowSIP[0];
		temppack->dim[1] <<= 8;
		temppack->dim[1] += temppack->lowSIP[1];

		temppack->dim[2] = temppack->highDIP[0];
		temppack->dim[2] <<= 8;
		temppack->dim[2] += temppack->highDIP[1];

		temppack->dim[3] = temppack->lowDIP[0];
		temppack->dim[3] <<= 8;
		temppack->dim[3] += temppack->lowDIP[1];

		temppack->dim[4] = temppack->sPort;
		temppack->dim[5] = temppack->dPort;

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
	char filename[] = "set2.txt";
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
		printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\nThe bmp[SIZE] is not long enougth, please set SIZE higher!!!\n");
		exit(0);
	}

}

// Check the result of the loaded filters, called by main
// return: void
void CheckData()
{
	// check the result of the loaded filters
	int filterNum=0;
	printf("Which filter you wanna check? 1 ~ %d : ",filtset.numFilters);
	scanf("%d", &filterNum);
	printf("\n----------The order of the rule is:\n");
	printf("%d",filtset.filtArr[filterNum].cost);
	printf("------------The start & end points of each dim is as follows:\n");
	for(int i=0;i<6;i++)
		printf("%d : %d\n",filtset.filtArr[filterNum].dim[i][0],filtset.filtArr[filterNum].dim[i][1]);
}

// Function to set bit value (0 or 1), called by SetPhase0_Cell
// call form : SetBmpBit(bmp,i,TRUE)
// Return : void
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

// Initialize listEqs, called by SetPhase0_Cell
// call form : InitListEqs(phase0_Nodes[i].listEqs)
// return : void
void InitListEqs(LISTEqS *ptrlistEqs)
{
	ptrlistEqs->nCES = 0;
	ptrlistEqs->head = NULL;
	ptrlistEqs->rear = NULL;
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

// Function to search bmp in listEqs, called by SetPhase0_Cell
// call form : SearchBmp(phase0_Nodes[i].listEqs,bmp)
// Return: if tbmp not exist in listEqs, return -1
// else return eqID of CES whose cbm matches tbmp
int SearchBmp(LISTEqS *ptrlistEqs,unsigned int *tbmp)
{
	CES *tCES;
	tCES = ptrlistEqs->head;
	for(int i=0;i<ptrlistEqs->nCES;i++){
		if(CompareBmp(tCES->cbm,tbmp))
			return i;
		else
			tCES = tCES->next;
	}
	return -1;
}

// Add new CES to ListEqs, called by SetPhase0_Cell
// call form : AddListEqsCES(phase0_Nodes[i].listEqs,bmp)
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

// Get rule cost number with highest priority, called by SetPhase2_Cell
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
	printf("!!! Lack of default rule!\nThere is no rule matched!\n");
	return -1;
}

// Free listEqs space, called by SetPhase1_Cell() & SetPhase2_Cell()
// Function : release space after table is established
// return : void
void FreeListEqs(LISTEqS *ptrlistEqs)
{
	if(ptrlistEqs->head == NULL)
		return;
	CES *tCES;

	for(int i=0;i<ptrlistEqs->nCES;i++){

		tCES = ptrlistEqs->head;
		ptrlistEqs->head = ptrlistEqs->head->next;
		free(tCES);
	}
	ptrlistEqs->rear = NULL;
}

// Function to fill the table of Phase 0, called by main
// return : void
void SetPhase0_Cell()
{
	// Chunk[0] to Chunk[5] of Phase 0
	for(unsigned int com=0;com<6;com++){
		
		unsigned int  bmp[SIZE];
		
		// Initialize bmp = 0
		for(int j=0;j<SIZE;j++)
			bmp[j] = 0;

		// Initialize phase0_Nodes[com]->listEqs
		InitListEqs(&phase0_Nodes[com].listEqs);

		// Scan through the number line looking for distinct equivalence classes
		for(unsigned int n=0;n<65536;n++){

			unsigned int tempstart,tempend;
			int tempeqID;

			// See if any rule starts or ends at n
			for(unsigned int i=0;i<filtset.numFilters;i++){
				
				// Dealing with different components
				tempstart = filtset.filtArr[i].dim[com][0];
				tempend   = filtset.filtArr[i].dim[com][1];

				// Update bmp if any rule starts or ends at n;
				if(tempstart == n)
					SetBmpBit(bmp,i,TRUE);
				if( (tempend+1) == n)
					SetBmpBit(bmp,i,FALSE);
			}
			
			// Search cbm of phase0_Nodes[com]->listEqs for bmp
			// return -1 if not exist, else return eqID
			tempeqID = SearchBmp(&phase0_Nodes[com].listEqs,bmp);
				
			// Not exist, add bmp to listEqs
			if (-1 == tempeqID)
				tempeqID = AddListEqsCES(&phase0_Nodes[com].listEqs,bmp);

			// Set Phase0 Cell bits
			phase0_Nodes[com].cell[n] = tempeqID;
		}
	}
}

// Find proper order to cut memory occupied
void FindOrder()
{
	bool flag;
	for(int m=0;m<6;m++)
		dot[m] = m;

	unsigned int tid[6];
	for(tid[0]=0;tid[0]<1;tid[0]++){
		for(tid[1]=tid[0]+1;tid[1]<5;tid[1]++){
			for(tid[2]=tid[1]+1;tid[2]<6;tid[2]++){

				// set tid[3] ~ tid[5]
				for(int i=3;i<6;i++){
					for(tid[i]=0;tid[i]<6;tid[i]++){
						flag = 1;
						for(int j=0;j<i;j++)
							if(tid[j] == tid[i]){
								flag = 0;
								break;
							}
						if(flag == 1)
							break;
					}
				}

				// find better order
				if( (phase0_Nodes[tid[0]].listEqs.nCES * phase0_Nodes[tid[1]].listEqs.nCES * phase0_Nodes[tid[2]].listEqs.nCES
					+phase0_Nodes[tid[3]].listEqs.nCES * phase0_Nodes[tid[4]].listEqs.nCES * phase0_Nodes[tid[5]].listEqs.nCES)
					< (phase0_Nodes[dot[0]].listEqs.nCES * phase0_Nodes[dot[1]].listEqs.nCES * phase0_Nodes[dot[2]].listEqs.nCES
					  +phase0_Nodes[dot[3]].listEqs.nCES * phase0_Nodes[dot[4]].listEqs.nCES * phase0_Nodes[dot[5]].listEqs.nCES) ){
				
					for(int i=0;i<6;i++)
						dot[i] = tid[i];
					}
			
			}
		}
	}
}


// Function to fill the table of Phase 1, called by main
// return : void
void SetPhase1_Cell()
{
	Pnode *tnode1, *tnode2, *tnode3;

	// Find order to cut memory occupied
	FindOrder();

	// Chunk[0] ~ Chunk[1] of Phase 1
	for(int com=0;com<2;com++){
		unsigned int indx = 0;
		int tempeqID;								

		// Initialize phase1_Nodes[com]->listEqs
		InitListEqs(&phase1_Nodes[com].listEqs);
		
		// Dealing with different component
		switch(com) {
			case 0:
				tnode1 = &phase0_Nodes[dot[0]];
				tnode2 = &phase0_Nodes[dot[1]];
				tnode3 = &phase0_Nodes[dot[2]];
				break;
			case 1:
				tnode1 = &phase0_Nodes[dot[3]];
				tnode2 = &phase0_Nodes[dot[4]];
				tnode3 = &phase0_Nodes[dot[5]];
				break;
			default:
				break;
		}
		
		// alloc memory for Phase1 cell
		unsigned int cellNum;
		cellNum = tnode1->listEqs.nCES * tnode2->listEqs.nCES * tnode3->listEqs.nCES;
		phase1_Nodes[com].ncells = cellNum;
		phase1_Nodes[com].cell = (unsigned short *) malloc (cellNum * sizeof(unsigned short));
		
		// generate phase1_Nodes[com]->listEqs
		CES *tCES1, *tCES2, *tCES3;
		unsigned int intersectedBmp[SIZE];
		
		tCES1 = tnode1->listEqs.head;
		for(int i=0;i<tnode1->listEqs.nCES;i++){
			
			tCES2 = tnode2->listEqs.head;
			for(int j=0;j<tnode2->listEqs.nCES;j++){
				
				tCES3 = tnode3->listEqs.head;
				for(int k=0;k<tnode3->listEqs.nCES;k++){
					
					// generate intersectedBmp
					for(int m=0;m<SIZE;m++)
						intersectedBmp[m] = tCES1->cbm[m] & tCES2->cbm[m] & tCES3->cbm[m];
						
					// Search cbm of phase1_Nodes[com]->listEqs for intersectedBmp
					// return -1 if not exist, else return eqID
					tempeqID = SearchBmp(&phase1_Nodes[com].listEqs,intersectedBmp);

					// Not exist, add intersectedBmp to listEqs
					if (-1 == tempeqID)
						tempeqID = AddListEqsCES(&phase1_Nodes[com].listEqs,intersectedBmp);

					// Set Phase1 Cell bits
					phase1_Nodes[com].cell[indx] = tempeqID;
					indx++;
					
					tCES3 = tCES3->next;
				}
				tCES2 = tCES2->next;
			}
			tCES1 = tCES1->next;
		}

		// Release listEqs Space
		FreeListEqs(&tnode1->listEqs);
		FreeListEqs(&tnode2->listEqs);
		FreeListEqs(&tnode3->listEqs);
	}
}


// Function to fill the table of Phase 2, called by main
// return : void
void SetPhase2_Cell()
{
	unsigned int indx = 0;
	Pnoder *tnode1, *tnode2;
	CES *tCES1, *tCES2;
	unsigned int endBmp[SIZE];
	unsigned int cost;								// cost number with highest priority
	
	tnode1 = &phase1_Nodes[0];
	tnode2 = &phase1_Nodes[1];

	// Initialize phase2_Node.listEqs
	InitListEqs(&phase2_Node.listEqs);

	// alloc memory for Phase1 cell
	unsigned int cellNum;
	cellNum = tnode1->listEqs.nCES * tnode2->listEqs.nCES;
	phase2_Node.ncells = cellNum;
	phase2_Node.cell = (unsigned short *) malloc (cellNum * sizeof(unsigned short));

	tCES1 = tnode1->listEqs.head;
	for(int i=0;i<tnode1->listEqs.nCES;i++){

		tCES2 = tnode2->listEqs.head;
		for(int j=0;j<tnode2->listEqs.nCES;j++){
			
			// generate endBmp
			for(int m=0;m<SIZE;m++)
				endBmp[m] = tCES1->cbm[m] & tCES2->cbm[m];

			// Get rule cost number with highest priority
			cost = GetRuleCost(endBmp);

			// Set Phase2 Cell bits
			phase2_Node.cell[indx] = cost;
			indx++;

			tCES2 = tCES2->next;
		}
		tCES1 = tCES1->next;
	}
	
	// Release listEqs Space
	FreeListEqs(&tnode1->listEqs);
	FreeListEqs(&tnode2->listEqs);
}

// Lookup, called by main
// the packages are in packageset.txt
// Result: save into lookupResult.txt
void Lookup()
{
	// Read packages from file packageset.txt
	FILE *fp;						// filter set file pointer
	char filename[] = "packageset.txt";
	fp = fopen(filename,"r");
	if (fp == NULL) 
	{
		printf("Cannot open package set file \n");
		exit (0);
	}
	LoadPackages(fp, &packageset);	// loading packages...
	fclose(fp);
	
	// Lookup process
	lookupResult = (unsigned short *) malloc (packageset.numPackages * sizeof(unsigned short));
	unsigned int cid[9];
	unsigned int indx[3];
	unsigned int line = 0;
	for(line=0;line<packageset.numPackages;line++){
		
		// phase 0
		for(int i=0;i<6;i++){
			cid[i] = phase0_Nodes[i].cell[packageset.PackArr[line].dim[i]];
		}
		
		// phase 1
		indx[0] = cid[dot[0]] * phase0_Nodes[dot[1]].listEqs.nCES * phase0_Nodes[dot[2]].listEqs.nCES
				 + cid[dot[1]] * phase0_Nodes[dot[2]].listEqs.nCES
				 + cid[dot[2]];
		indx[1] = cid[dot[3]] * phase0_Nodes[dot[4]].listEqs.nCES * phase0_Nodes[dot[5]].listEqs.nCES
				 + cid[dot[4]] * phase0_Nodes[dot[5]].listEqs.nCES
				 + cid[dot[5]];
		cid[6] = phase1_Nodes[0].cell[indx[0]];
		cid[7] = phase1_Nodes[1].cell[indx[1]];
		
		// phase 2
		indx[2] = cid[6] * phase1_Nodes[1].listEqs.nCES + cid[7];
		
		// store lookup result into lookupResult[]
		lookupResult[line] = phase2_Node.cell[indx[2]];
	}

	printf("\nLookup finished!\n");

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

// count memory : memory occupied by chunks
void CountMemory()
{
	unsigned int cellused;
	unsigned int numbits;
	numbits = sizeof(unsigned short);
	cellused = 65536 * 6;
	cellused += phase1_Nodes[0].ncells;
	cellused += phase1_Nodes[1].ncells;
	cellused += phase2_Node.ncells;
	cellused *= numbits;
	printf("\nMemory used by chunks : %d bytes\n",cellused);
	
	// store memory used int memoryused.txt
	FILE *fp;
	char filename[] = "memoryused.txt";
	fp = fopen(filename,"w+");
	if (fp == NULL) 
	{
		printf("Cannot open memoryused file \n");
		exit (0);
	}
	
	fprintf(fp,"\nMemory used by chunks : %d bytes\n",cellused);
	fprintf(fp,"\nMemory used by phase0_Nodes[0~5] is : %d bytes\n\n",65536*6*numbits);
	for(int i=0;i<6;i++)
		fprintf(fp,"The CES amount of phase0_Nodes[%d] is : %d\n",i,phase0_Nodes[i].listEqs.nCES);
	fprintf(fp,"\n");
	for(i=0;i<2;i++){
		fprintf(fp,"Memory used by phase1_Nodes[%d] is : %d bytes\n",i,phase1_Nodes[i].ncells*numbits);
		fprintf(fp,"The CES amount of phase1_Nodes[%d] is : %d\n",i,phase1_Nodes[i].listEqs.nCES);
	}
	fprintf(fp,"\nMemory used by phase2_Node is : %d bytes\n",phase2_Node.ncells*numbits);
	fclose(fp);
}

// save preprocessing result to chunkdata.txt
void SaveChunks()
{
	FILE *fp;
	char filename[] = "chunkdata.txt";
	fp = fopen(filename,"w+");
	if (fp == NULL) 
	{
		printf("Cannot open chunkdata.txt file \n");
		exit (0);
	}
	
	// Save phase0 chunks
	unsigned int i,j;
	/////////////////////////////////////////////////////////////////////////
	// Save phase0 chunk data
	for(i=0;i<6;i++)
		for(j=0;j<65536;j++)
			fprintf(fp,"%d\t",phase0_Nodes[i].cell[j]);

	// Save CES amount of chunk
	for(i=0;i<6;i++)
		fprintf(fp,"%d\t",phase0_Nodes[i].listEqs.nCES);
	
	//////////////////////////////////////////////////////////////////////////
	// Save phase1 chunks
	for(i=0;i<2;i++){
		// Save phase1 chunk cell numbers
		fprintf(fp,"%d\t",phase1_Nodes[i].ncells);
		for(j=0;j<phase1_Nodes[i].ncells;j++){
			fprintf(fp,"%d\t",phase1_Nodes[i].cell[j]);
		}
	}
	// Save CES amount of chunk
	for(i=0;i<2;i++)
		fprintf(fp,"%d\t",phase1_Nodes[i].listEqs.nCES);

	///////////////////////////////////////////////////////////////////////////
	// Save phase2 chunk cell numbers
	fprintf(fp,"%d\t",phase2_Node.ncells);
	// Save phase2 chunk
	for(j=0;j<phase2_Node.ncells;j++)
		fprintf(fp,"%d\t",phase2_Node.cell[j]);

	fclose(fp);
}

// load preprocessing result from chunkdata.txt
void LoadChunks()
{
	FILE *fp;
	char filename[] = "chunkdata.txt";
	fp = fopen(filename,"r");
	if (fp == NULL) 
	{
		printf("Cannot open chunkdata.txt file \n");
		exit (0);
	}	

	///////////////////////////////////////////////////
	// Load phase0 chunks
	unsigned int i,j;
	unsigned short tnCES;

	// Read chunk data
	for(i=0;i<6;i++)
		for(j=0;j<65536;j++){
			fscanf(fp,"%d",&phase0_Nodes[i].cell[j]);
		}
	// Read CES amount of chunk
	for(i=0;i<6;i++){
		fscanf(fp,"%d",&tnCES);
		phase0_Nodes[i].listEqs.nCES = tnCES;
	}

	////////////////////////////////////////////////////
	// Load phase1 chunks
	for(i=0;i<2;i++){
		// Read phase1 chunk cell numbers
		fscanf(fp,"%d",&phase1_Nodes[i].ncells);
		
		// Allocate memory for phase1_Node[i] cells
		phase1_Nodes[i].cell = (unsigned short *) malloc (phase1_Nodes[i].ncells * sizeof(unsigned short));
		
		// Load phase1_Nodes[i] chunk data
		for(j=0;j<phase1_Nodes[i].ncells;j++){
			fscanf(fp,"%d",&phase1_Nodes[i].cell[j]);
		}
	}

	//Read CES amount of chunk
	for(i=0;i<2;i++){
		fscanf(fp,"%d",&tnCES);
		phase1_Nodes[i].listEqs.nCES = tnCES;
	}

	////////////////////////////////////////////////////
	// Read phase2 chunk cell numbers
	fscanf(fp,"%d",&phase2_Node.ncells);

	// Allocate memory for phase2_Node cells
	phase2_Node.cell = (unsigned short *) malloc (phase2_Node.ncells * sizeof(unsigned short));

	// Load phase2 chunk data
	for(j=0;j<phase2_Node.ncells;j++)
		fscanf(fp,"%d",&phase2_Node.cell[j]);	

	fclose(fp);
}


// preprocessing according to filterset
// Aim : To establish the chunks & save to file chunkdata.txt
void Preprocess()
{
	int time = GetTickCount();
	SetPhase0_Cell();
	time = GetTickCount() - time;
	printf("Time of phase0 is %d ms \n",time);
	SetPhase1_Cell();
	SetPhase2_Cell();
	CountMemory();
//	SaveChunks();
}

int main(int argc, char* argv[])
{

///////////////////////////////////////////////////////////////////////////
// reading data 
	ReadFilterFile();

// check the result of the loaded filters
//	CheckData();

// preprocessing according to filterset
// used for new filterset 

	int time;
	time = GetTickCount();
	Preprocess();
	time = GetTickCount() - time;
	printf("Time used for preprocessing is %d ms\n",time);

// load chunk data from file chunkdata.txt
// used when filterset is not changed
//	LoadChunks();

//	Lookup();

	return 0;
}