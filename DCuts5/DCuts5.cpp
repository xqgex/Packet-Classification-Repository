// DCuts4.cpp	Dynamic Cuttings
// Version		5.0
// Auther		BabyQi
// Description	using Breadth First way to build decision tree

#include <STDIO.H>
#include <STDLIB.H>
#include <MEMORY.H>
#include <MATH.H>
#include <CONIO.H>

#include "DCuts5.h"

// #define BOUND(a) ((((a>SPFAC_MIN)?a:SPFAC_MIN)<SPFAC_MAX)?a:SPFAC_MAX)
#define BOUND(spfac_pv, spfac_max, spfac_min) ((((spfac_pv>spfac_max)?spfac_max:spfac_pv)<spfac_min)? spfac_min:spfac_pv)

/************************************************************************/
/* functions for loading rules                                          */
/************************************************************************/
void ReadPrefix(FILE *fp, unsigned char *IPpref, unsigned char *IPmask)
{
	unsigned int tpref[4], tMask;
	tMask = 32;	// default mask length for ip address(with no '/??' specification)
	
	fscanf(fp,"%d.%d.%d.%d/%d",&tpref[0],&tpref[1],&tpref[2],&tpref[3], &tMask);
	IPpref[0] = (unsigned char)tpref[0];
	IPpref[1] = (unsigned char)tpref[1];
	IPpref[2] = (unsigned char)tpref[2];
	IPpref[3] = (unsigned char)tpref[3];
	*IPmask	  = (unsigned char)tMask;
}

void ReadPort(FILE *fp, unsigned int *Pt)
{
	fscanf(fp,"%d : %d", &Pt[0], &Pt[1]);
}


int ReadRules(FILE *fp, unsigned int pos)
{
	/*allocate a few more bytes just to be on the safe side to avoid overflow etc*/
	char validRule;// validRule means an '@'
	struct RULE tempRule;
	
	while(TRUE)
	{
		// each rule should begin with an '@' 
		fscanf(fp,"%c",&validRule);
		if (validRule != '@') continue;
		
		unsigned char	sIP[4], dIP[4], sIPmask, dIPmask;
		ReadPrefix(fp, sIP, &sIPmask);		// reading sIP prefix and mask
		ReadPrefix(fp, dIP, &dIPmask);		// reading dIP prefix and mask
		//	express 4 bytes IP by 32bits HEX number
		unsigned int sIPHEX =  (sIP[0] << 24)^(sIP[1] << 16)^(sIP[2] << 8)^(sIP[3]); 
		unsigned int dIPHEX =  (dIP[0] << 24)^(dIP[1] << 16)^(dIP[2] << 8)^(dIP[3]); 
		unsigned int sIPMask = (0xffffffff>>(32-sIPmask))<<(32-sIPmask);
		unsigned int dIPMask = (0xffffffff>>(32-dIPmask))<<(32-dIPmask);
		if(sIPmask==0)	sIPMask = 0x0;	// shit for intel CPU!!
		if(dIPmask==0)	dIPMask = 0x0;	// shit again
		tempRule.ruleRange[0][0] = sIPHEX&sIPMask;	tempRule.ruleRange[0][1] = sIPHEX|(~sIPMask);	
		tempRule.ruleRange[1][0] = dIPHEX&dIPMask;	tempRule.ruleRange[1][1] = dIPHEX|(~dIPMask);
		
		unsigned int	sPt[2], dPt[2];
		ReadPort(fp, sPt);	// reading sPt
		ReadPort(fp, dPt);	// reading dPt
		tempRule.ruleRange[2][0]=sPt[0];	tempRule.ruleRange[2][1]=sPt[1];
		tempRule.ruleRange[3][0]=dPt[0];	tempRule.ruleRange[3][1]=dPt[1];	
		
		// read the cost (position)
		tempRule.pos = pos;
		
		// copy the temp filter to the global one
		memcpy(&(ruleSet.ruleList[ruleSet.numRules]), &tempRule, sizeof(struct RULE));
		
		ruleSet.numRules++;	   
		return SUCCESS;
	}
}

void LoadRules(FILE *fp)	// load 
{
	
	ruleSet.numRules=0;
	unsigned int pos = 0;	// the posisiton of the rules
	while(!(feof(fp))) 
	{
		pos++;
		ReadRules(fp, pos);
	}
}

/************************************************************************/
/* functions for building trees                                         */
/************************************************************************/
int ReadHeader(FILE *fp)
{
	char validHeader;// validfilter means an '@'
	unsigned int tpref[4];	// temporary variables to store IP prefix and its lenght
	struct HEADER tHeader;
	while (!(feof(fp)))
	{
		fscanf(fp,"%c",&validHeader);
		if (validHeader != '@') continue;	// each header should begin with an '@' 
		// reading sIP and dIP
		fscanf(fp,"%d.%d.%d.%d",&tpref[0],&tpref[1],&tpref[2],&tpref[3]);
		tHeader.dim[0] =  (tpref[0] << 24)^(tpref[1] << 16)^(tpref[2] << 8)^(tpref[3]); 
		fscanf(fp,"%d.%d.%d.%d",&tpref[0],&tpref[1],&tpref[2],&tpref[3]);
		tHeader.dim[1] =  (tpref[0] << 24)^(tpref[1] << 16)^(tpref[2] << 8)^(tpref[3]); 
		fscanf(fp,"%d	%d",&tHeader.dim[2], &tHeader.dim[3]);
		// copy the temp header to the global one
		memcpy(&(headerSet.headerList[headerSet.numHeaders]), &tHeader, sizeof(struct HEADER));
		headerSet.numHeaders++;	   
		//		printf("\n>>HEADER: sIP=%x, dIP=%x, sPt=%x, dPt=%x\n", header->dim[0], header->dim[1], header->dim[2], header->dim[3]);
		return SUCCESS;
	}
	return FALSE;
}

void LoadHeaders(FILE *fp)	// load packet headers
{
	headerSet.numHeaders = 0;
	while(!(feof(fp))) 
	{
		ReadHeader(fp);
	}
}

int LoadPrior(char dims)
{
	unsigned int dim, num, pos;
	for(dim=0; dim<4; dim++)
	{
		if((dims>>dim)&((char)0x1))
		{
			for(num=0; num<headerSet.numHeaders; num++)
			{
				if(dim<2)
				{
					pos = (headerSet.headerList[num].dim[dim]>>16);
				}
				else
					pos = headerSet.headerList[num].dim[dim];
				gNts.prior[dim][pos] += 1/((float)headerSet.numHeaders);
			}
		}
		else
		{
			for(num=0; num<65536; num++)
				gNts.prior[dim][num]=0;
		}
	}
	return SUCCESS;
};
int PreCut(unsigned char dimToCut, unsigned int currRange[4][2], unsigned int numRules, float spfac, unsigned int *currRuleList, struct CUTTING *tempCut)
{	
	unsigned int i, num, cut;
	unsigned int cuts = 1;	// 
	unsigned int numCuts = 1;	// number of cuts is 2^numCuts 
	// TODO:refer to HiCuts for alternative initialization of numCuts
	
	unsigned int spaceAvailable = (unsigned int) (numRules*spfac);	// space available
	unsigned int smC=0;	// space measurement
	
	unsigned int rangeToSearch[2];	// search this range for the number of colliding rules
	unsigned int interval = currRange[dimToCut][1]-currRange[dimToCut][0];	// interval is always 2^cut
	
	float costs[4], worstCosts[4];
	for(i=0; i<4; i++)	worstCosts[i] = 0;
	
	// decide if current search range really need to cut
	for(num=0; num<numRules; num++)	// how many rules cover the full search range
	{	
		if(ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][0]<=currRange[dimToCut][0] 
			&& ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][1]>=currRange[dimToCut][1])
		{
			smC++;
		}
	}
	if(smC == numRules)
	{
		return FALSE;	// all rules cover the full search space, so it's of no use to cut anymore
	}
	
	// cutting with the limit of spaceAvailable	
	while(TRUE)
	{
		smC = 0;	// space measurement
		interval = (interval>>1)+1;	// interval/2
		numCuts = (0x1<<cuts);
		costs[1] = 0;
		for(cut=0; cut<numCuts; cut++)
		{
			// 划分出来的区间
			rangeToSearch[0] = currRange[dimToCut][0]+cut*interval;
			rangeToSearch[1] = rangeToSearch[0]+interval-1;	// -1为了避免越界, 比如出现0xffffffff+1的问题
			costs[0] = 0;
			for(num=0; num<numRules; num++)	// how many rules collide with this range
			{	
				if(ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][0]>=rangeToSearch[0] 
					&& ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][0]<=rangeToSearch[1])
				{
					smC++;
					costs[0]++;	
				}
				else if(ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][1]>=rangeToSearch[0] 
					&& ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][1]<=rangeToSearch[1])
				{
					smC++;
					costs[0]++; 
				}
				else if(ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][0]<rangeToSearch[0] 
					&& ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][1]>rangeToSearch[1])
				{
					smC++;
					costs[0]++;
				}
			}
			costs[1]+=costs[0];
			if(worstCosts[0]<costs[0])
			{
				worstCosts[0] = costs[0];
			}
		}
		costs[1] = costs[1]/numCuts;	// average number of rules falling in each child node
		if(worstCosts[1]<costs[1])
		{
			worstCosts[1] = costs[1];
		}

		smC+=numCuts;
		
		if(smC<spaceAvailable && (interval>1))
		{	
			cuts++;	// twice larger than current number of cuttings
			interval--;
			for(i=0; i<4; i++)	worstCosts[i] = 0;
		}
		else
		{
			tempCut->dimToCut = dimToCut;
			tempCut->numCuts = cuts; 
			for(i=0; i<4; i++)
				tempCut->costs[i] = worstCosts[i];
			return SUCCESS;
		}
	}
}

int BuildTree(struct TREENODE *rootNode)
{
	unsigned int num, dim, cut;
	unsigned int currRange[4][2] = {{0, 0xffffffff}, {0, 0xffffffff}, {0, 0xffff}, {0, 0xffff}};
	unsigned int currNumRules = ruleSet.numRules;
	float		 currSpfac = SPFAC_AVG;
	float		 currPv = 1;
	float		 K;
	unsigned int currLevel = 1;
	unsigned int currNumNodes = 1;
	unsigned int *currRuleList = (unsigned int*)malloc(currNumRules*sizeof(unsigned int));
	// FAQ: why i allocate so much memory here? --just for convenience.
	
	// initial decision tree
	struct TREENODE *currNode = rootNode;
	currNode->nodeInfo = 0;
	currNode->depth = 1;
	
	// initial queues
	struct QUEUE currQueue, nextQueue;

	currQueue.head = (QUEUENODE *)malloc(sizeof(struct QUEUENODE));	
	currQueue.rear = currQueue.head; currQueue.numNodes = currNumNodes;
	currQueue.Pv_max = 0; currQueue.Pv_min = 0;
	memcpy((unsigned int *)currQueue.head->currRange, (unsigned int *)currRange, 4*2*sizeof(unsigned int));
	currQueue.head->numRules = currNumRules;
	currQueue.head->spfac = currSpfac;
	currQueue.head->currPv = currPv;
	currQueue.head->nodeLevel = currLevel;
	currQueue.head->ruleList = (unsigned int*)malloc(currNumRules*sizeof(unsigned int));
	for(num=0; num<currNumRules; num++)	currQueue.head->ruleList[num] = num;	// all rules belong to the root node
	currQueue.head->currTNode = currNode;	
	currQueue.head->nextNode = NULL;

	nextQueue.head = NULL; nextQueue.rear = NULL;
	nextQueue.numNodes = 0; nextQueue.Pv_max = 0; nextQueue.Pv_min = 1;
	struct QUEUENODE *prevQueueNode;	// for deleting node

	unsigned int	sumDepth=0, worstDepth=0;
	unsigned int	numLeaves=0;
	
	while(TRUE)
	{
		////	pop out a tree node from the stack
		currNode = currQueue.head->currTNode;
		// update common variables
		currNumRules = currQueue.head->numRules;
		currSpfac = currQueue.head->spfac;
		currPv = currQueue.head->currPv;
		currLevel = currQueue.head->nodeLevel;
		currNumNodes = currQueue.numNodes;
		if(currQueue.Pv_max-currQueue.Pv_min>0.01)
			K = (SPFAC_MAX-SPFAC_MIN)/(currQueue.Pv_max-currQueue.Pv_min);
		else
			K = 0;
		memcpy((unsigned int *)currRuleList, (unsigned int*)currQueue.head->ruleList, currNumRules*sizeof(unsigned int));
		memcpy((unsigned int *)currRange, (unsigned int *)currQueue.head->currRange, 4*2*sizeof(unsigned int));
		// 		printf("\n>>CURRRANGE:");	for(dim=0; dim<4; dim++)	printf("[%x, %x] ", currRange[dim][0], currRange[dim][1]);
// 		printf("\n>>POPOUT:");	for(num=0; num<currNumRules; num++)	printf("%u, ", currRuleList[num]+1);
		////	set rules belong to current node
		if(currNumRules<=BINTH)	// how to treat a leaf node
		{
			currNode->nodeInfo = currNumRules;
			currNode->next = (unsigned int *)malloc(currNumRules*sizeof(unsigned int));
			memcpy((unsigned int*)currNode->next, (unsigned int*)currRuleList, currNumRules*sizeof(unsigned int));

			//>>COUNT
			numLeaves++;
			sumDepth+=currNode->depth;
			gResult.totalMem+=currNumRules*4;

		}
		else	// how to treat an internal node...
		{	
			// choose which dimension(field) to cut this time
			struct CUTTING bestCut, tempCut;
			bestCut.costs[0] = (float)currNumRules;
			bestCut.costs[1] = (float)currNumRules;
			for(dim=0; dim<4; dim++)
			{ 
				if(PreCut((unsigned char)dim, currRange, currNumRules, currSpfac, currRuleList, &tempCut) == SUCCESS)
				{				
					if(tempCut.costs[0]<=bestCut.costs[0])	// record the best cut scheme in bestCut
					{
						bestCut.dimToCut=tempCut.dimToCut ; bestCut.numCuts=tempCut.numCuts; bestCut.costs[0]=tempCut.costs[0];
					}
					if(tempCut.costs[1]<=bestCut.costs[1])	// record the best cut scheme in bestCut
					{
						bestCut.dimToCut=tempCut.dimToCut ; bestCut.numCuts=tempCut.numCuts; bestCut.costs[1]=tempCut.costs[1];
					}
				}
			}
			printf("\n>>BESTCUTS: dimCut:%u; numCut:%u; cost:%f", bestCut.dimToCut, bestCut.numCuts, bestCut.costs[0]);	//optimizing worst case
//			printf("\n>>BESTCUTS: dimCut:%u; numCut:%u; cost:%f", bestCut.dimToCut, bestCut.numCuts, bestCut.costs[1]); //optimizing average case
			
			// update current tree node
			currNode->dimToCut = bestCut.dimToCut;	currNode->numCuts = bestCut.numCuts;
			unsigned int numCuts = (0x1<<currNode->numCuts);
			unsigned char dimToCut = currNode->dimToCut;
			currNode->next = (struct TREENODE*)malloc(numCuts*sizeof(struct TREENODE));	// first child
			nextQueue.numNodes+=numCuts;
			struct TREENODE *childNodes = (struct TREENODE*)currNode->next;
			// allocate successive memory for children, currNode->next points to his first child
			
			//>> COUNT
			for(cut=0; cut<numCuts; cut++)
				childNodes[cut].depth = currNode->depth+1;
			if(worstDepth<currNode->depth+1)
				worstDepth = currNode->depth+1;
			gResult.totalMem+=numCuts*7;
			gResult.numNodes+=numCuts;
			
			// assign corresponding ruleset for each child tree node
			unsigned int rangeToSearch[2];
			unsigned int tempRange[4][2];
			memcpy((unsigned int *)tempRange, (unsigned int *)currRange, 4*2*sizeof(unsigned int));
			// store colliding rules for each child
			unsigned int tempNumRules; // number of rules in each child node
			unsigned int *tempRuleList = (unsigned int *)malloc(currNumRules*sizeof(unsigned int));
			struct QUEUENODE *tempQueueNode;
			
			// priori for node v
			float Pv=0;
			unsigned int A, B, ab;
			for(dim=0; dim<2; dim++)
			{
				if(dim!=(unsigned int)dimToCut)
				{
					A = (currRange[dim][0]>>16);	B = (currRange[dim][1]>>16);
					for(ab=A; ab<=B; ab++)
						Pv+=gNts.prior[dim][ab];
				}
			}
			for(dim=2; dim<4; dim++)
			{	
				if(dim!=(unsigned int)dimToCut)
				{
					A = currRange[dim][0]; B = currRange[dim][1];
					for(ab=A; ab<=B; ab++)
						Pv+=gNts.prior[dim][ab];
				}
			}

			unsigned int interval = ((currRange[dimToCut][1]-currRange[dimToCut][0])>>currNode->numCuts)+1;
			for(cut=0; cut<numCuts; cut++)	// compute N and spfac for each 
			{
				tempNumRules = 0;
				rangeToSearch[0] = currRange[dimToCut][0]+cut*interval;
				rangeToSearch[1] = rangeToSearch[0]+interval-1;

				if(dimToCut<2)
				{
					A = (rangeToSearch[0]>>16);	B = (rangeToSearch[1]>>16);
					for(ab=A; ab<=B; ab++)
						Pv+=gNts.prior[dimToCut][ab];
				}
				else
				{
					A = rangeToSearch[0]; B = rangeToSearch[1];
					for(ab=A; ab<=B; ab++)
						Pv+=gNts.prior[dimToCut][ab];
				}
 				Pv = Pv/2;	// just count dIP and sPt
				if(nextQueue.Pv_max<Pv)	
					nextQueue.Pv_max=Pv;
				if(nextQueue.Pv_min>Pv)	
					nextQueue.Pv_min=Pv;

				for(num=0; num<currNumRules; num++)	
				{	
					if(ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][0]>=rangeToSearch[0] 
						&& ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][0]<=rangeToSearch[1])
					{
						tempNumRules++;
						tempRuleList[tempNumRules-1] = currRuleList[num];
					}
					else if(ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][1]>=rangeToSearch[0] 
						&& ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][1]<=rangeToSearch[1])
					{
						tempNumRules++;
						tempRuleList[tempNumRules-1] = currRuleList[num];
					}
					else if(ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][0]<rangeToSearch[0] 
						&& ruleSet.ruleList[currRuleList[num]].ruleRange[dimToCut][1]>rangeToSearch[1])
					{
						tempNumRules++;
						tempRuleList[tempNumRules-1] = currRuleList[num];
					}
				}
				if(tempNumRules>0)	// if there's any rule collides with this child node
				{
					currNode->nodeInfo = 0;	// no rules collides with this node, except for the defalt rule
					tempQueueNode = (struct QUEUENODE *)malloc(sizeof(struct QUEUENODE));
					tempQueueNode->numRules = tempNumRules;
					tempRange[dimToCut][0] = rangeToSearch[0]; tempRange[dimToCut][1] = rangeToSearch[1];
					memcpy((unsigned int *)tempQueueNode->currRange, (unsigned int *)tempRange, 4*2*sizeof(unsigned int));
					tempQueueNode->currTNode = &childNodes[cut];
					tempQueueNode->ruleList = (unsigned int *)malloc(tempNumRules*sizeof(unsigned int));
					memcpy((unsigned int*)tempQueueNode->ruleList, (unsigned int*)tempRuleList, tempNumRules*sizeof(unsigned int));
					switch(ALGORITHM) 
					{
					case 1:	// BABYQI
						if(K!=0)
							tempQueueNode->spfac = (float)((currPv-currQueue.Pv_min)*K)+SPFAC_MIN;
						else
							tempQueueNode->spfac = SPFAC_AVG;
						break;
					case 2: // DONGYI
						tempQueueNode->spfac = currPv*currNumNodes*SPFAC_AVG;
						if(tempQueueNode->spfac>SPFAC_MAX-1)	tempQueueNode->spfac = SPFAC_MAX-1;
						if(tempQueueNode->spfac<SPFAC_MIN)	tempQueueNode->spfac = SPFAC_MIN;
						break;
					default:
						tempQueueNode->spfac = SPFAC_ORG;
					}
					tempQueueNode->currPv = Pv;
					//printf("\n>>SPFAC:%5f", tempQueueNode->spfac);

					if(nextQueue.head == NULL)	// next level begin
					{
						nextQueue.head = tempQueueNode;
						nextQueue.rear = nextQueue.head;
					}
					else	// appending to next level
					{
						nextQueue.rear->nextNode = tempQueueNode;
						nextQueue.rear = nextQueue.rear->nextNode;
					}
				}
				else
				{
					childNodes[cut].nodeInfo = -1;	// no rules collides with this node, except for the defalt rule
					childNodes[cut].dimToCut = 0; 
					childNodes[cut].numCuts = 0;
					childNodes[cut].next = NULL;
				}
			}
			free(tempRuleList);
		}//if...else
		// Pop out a node
		if(currQueue.head == currQueue.rear)
		{
			free(currQueue.head);
			currQueue.head = nextQueue.head;	currQueue.rear = nextQueue.rear;
			currQueue.numNodes = nextQueue.numNodes; 
			currQueue.Pv_max = nextQueue.Pv_max;
			currQueue.Pv_min = nextQueue.Pv_min;
			nextQueue.head = NULL; nextQueue.rear = NULL;	nextQueue.numNodes = 0;
			nextQueue.Pv_max = 0; nextQueue.Pv_min = 1; 
		}
		else
		{
			prevQueueNode = currQueue.head;
			currQueue.head = currQueue.head->nextNode;
			free(prevQueueNode);
		}
		
		if(currQueue.head == NULL)	// no node in queue
		{
			free(currRuleList);	// delete common variables
			gResult.avgDepth = (float)sumDepth/numLeaves;
			gResult.wstDepth = worstDepth;
			return SUCCESS;
		}


	}//while(TRUE)
}


/************************************************************************/
/* functions for classification                                         */
/************************************************************************/

int LinearSearch(unsigned int headerNumber, unsigned int *ruleList, char numRules)
{
	int leastCostRule = ruleSet.numRules;
	int	rulePos;
	unsigned int	dim, num;
	struct HEADER *header = &headerSet.headerList[headerNumber];

	for(num=0; num<(unsigned int)numRules; num++)
	{	
		rulePos = ruleList[num];
		for(dim=0; dim<4; dim++)
		{
			if(header->dim[dim]<ruleSet.ruleList[rulePos].ruleRange[dim][0]
				|| header->dim[dim]>ruleSet.ruleList[rulePos].ruleRange[dim][1])
				goto next_rule;
		}
		if(leastCostRule>rulePos)
			leastCostRule = ruleList[num];
next_rule:
		continue;
	}
	return ++leastCostRule;
}

int Filtering(unsigned int headerNumber, struct TREENODE *rootNode)
{	
	unsigned int dim;
	unsigned int currRange[4][2] = {{0, 0xffffffff}, {0, 0xffffffff}, {0, 0xffff}, {0, 0xffff}};// current search space
	unsigned char currCuts[4] = {32, 32, 16, 16};
	unsigned int bias, interval, cuts;
	struct TREENODE *currNode = rootNode;
	unsigned int *ruleList;
	char nodeInfo;
	struct HEADER *header = &headerSet.headerList[headerNumber];
	float searchTime=0;
	
	while(TRUE)
	{
		nodeInfo = currNode->nodeInfo;
		if(nodeInfo == 0)	// get an internal nodes
		{
			searchTime+=2;

			cuts = (unsigned int)currNode->numCuts;
			dim = (unsigned int)currNode->dimToCut;
			interval = ((currRange[dim][1]-currRange[dim][0])>>cuts)+1;
			currCuts[dim] = currCuts[dim]-cuts;
 			bias = (unsigned int)((header->dim[dim]-currRange[dim][0])>>currCuts[dim]);
			currRange[dim][0] = (unsigned int)((header->dim[dim]>>currCuts[dim])<<currCuts[dim]);
			currRange[dim][1] = currRange[dim][0]+interval-1;
			currNode = (struct TREENODE*)currNode->next + bias;

//			cuts = (unsigned int)currNode->numCuts;
//			dim = (unsigned int)currNode->dimToCut;
//			interval = ((currRange[dim][1]-currRange[dim][0])>>cuts)+1;
//			bias = (unsigned int) ((header->dim[dim]-currRange[dim][0])/interval);
//			currRange[dim][0] = currRange[dim][0]+interval*bias;
//			currRange[dim][1] = currRange[dim][0]+interval-1;
//			currNode = (struct TREENODE*)currNode->next + bias;
			
// 			printf("currDim=%u, bias=%u, cuts=%u, nodeInfo=%d\n", dim, bias, cuts, nodeInfo);
//			printf("interval=%x, currRange=[%x, %x], rangewidth=%x\n", interval, currRange[dim][0], currRange[dim][1], currRange[dim][1]-currRange[dim][0]);
		}
		else if(nodeInfo > 0)	// get a common leaf node
		{
			ruleList = (unsigned int*)currNode->next;
			printf("\n>>The packet satisfys:the No.%d Rule", LinearSearch(headerNumber, ruleList, nodeInfo));
//			for(i=0; i<(unsigned int)nodeInfo; i++)	printf("%5u ", ruleList[i]+1);
			searchTime = searchTime + nodeInfo*6;
			gResult.numPackets++;
			gResult.avgSearchTime+=searchTime;
			if(searchTime>=gResult.wstSearchTime)	gResult.wstSearchTime = (unsigned int)searchTime;
			return SUCCESS;
		}
		else // get a leaf nodes with just the default rule
		{
			printf("\n>>The packet satisfys:default");
			return SUCCESS;
		}
	}
	
	return ERROR;
}



//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
int main(int argc, char* argv[])
{
	gResult.avgDepth = 0;	
	gResult.wstDepth = 0;	
	gResult.numLeaves= 0;	
	gResult.numNodes = 1;	// for root node
	gResult.totalMem = 7;	// for root node

	gResult.avgSearchTime = 0;
	gResult.wstSearchTime = 0;
	gResult.numPackets = 0;



	////	LOADING RULES
	printf(">>Loading rules...");
	FILE *fp;
	fp = fopen(ruleFile,"r");
	if(fp == NULL) 
	{
		printf("\n>>ERROR:Couldnt open rule set file.");
		exit(0);
	}
	LoadRules(fp);	// loading filters...
	fclose(fp);
	printf("\n>>Number of rules loaded: %d",ruleSet.numRules);
	//print each rule
	//	int i, j;
	//	for(j=0; j<4; j++)
	//		for(i=0; i<1; i++)//ruleSet.numRules; i++)
	//			printf("rule%d dim%d: %u~%u\n",i, j, ruleSet.ruleList[i].ruleRange[j][0], ruleSet.ruleList[i].ruleRange[j][1]);

	////	LOADING NETWORK CHARACTERISTICAL STATISTICS(NCS)
	// load packet headers(sample headers)
	fp = fopen(headerFile,"r");
	if(fp==NULL) 
	{
		printf("\n>>ERROR:Couldnt open header file.");
		exit (0);
	}
	LoadHeaders(fp);
	fclose(fp);
	printf("\n>>Number of headers loaded: %d\n", headerSet.numHeaders);
	LoadPrior(0x6);	// for set0, set1, set2, set3
//	LoadPrior(0xA); // for set2, set3
	
	////	BUIDLING DECISION TREE
	struct TREENODE rootNode;	// create rootNode for decision tree
	if(!BuildTree(&rootNode))
	{
		printf("\n>>ERROR:Something wrong when building our tree.");
		exit(0);
	}
	printf("\n>>Finish building the decision tree.");
	// TODO: save the tree in a file

	////	PACKET CLASSIFICATION
//	struct HEADER header;

	unsigned int num;
	for(num=0; num<headerSet.numHeaders; num++)
	{
		Filtering(num, &rootNode);
	}

	////	RESULTS
	printf("\n>>MEMORY USAGE:%u(KB)", gResult.totalMem>>10);
	printf("\n>>TREE DEPTH: %f(average), %u(worstcase)", gResult.avgDepth, gResult.wstDepth);
	printf("\n>>SEARCH TIME:%f(average), %u(worstcase)", gResult.avgSearchTime/gResult.numPackets, gResult.wstSearchTime);\
	printf("\n>>END CLASSIFICATION\n");
	
	
	return 0;
}