// HiCuts3.c	algorithm for Packet Classification
// Version		3.0
// Auther		BabyQi
// Description	Add more criteria for cuttings

#include <STDIO.H>
#include <STDLIB.H>
#include <MEMORY.H>
#include <MATH.H>
#include <CONIO.H>

#include "HiCuts3.h"

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


int ReadRules(FILE *fp, struct RULESET *ruleSet, unsigned int pos)
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
		memcpy(&(ruleSet->ruleList[ruleSet->numRules]), &tempRule, sizeof(struct RULE));
		
		ruleSet->numRules++;	   
		return SUCCESS;
	}
}

void LoadRules(FILE *fp, struct RULESET *ruleSet)	// load 
{
	
	ruleSet->numRules=0;
	unsigned int pos = 0;	// the posisiton of the rules
	while(!(feof(fp))) 
	{
		pos++;
		ReadRules(fp, ruleSet, pos);
	}
}

/************************************************************************/
/* functions for building trees                                         */
/************************************************************************/
int PreCut(unsigned char dimToCut, unsigned int currRange[4][2], unsigned int numRules, unsigned int *currRuleList, struct CUTTING *tempCut, struct RULESET *ruleSet)
{	
	unsigned int i, num, cut;
	unsigned int cuts = 1;	// 
	unsigned int numCuts = 1;	// number of cuts is 2^numCuts 
	// TODO:refer to HiCuts for alternative initialization of numCuts
	
	unsigned int spaceAvailable = numRules*SPFAC;	// space available
	unsigned int smC=0;	// space measurement
	
	unsigned int rangeToSearch[2];	// search this range for the number of colliding rules
	unsigned int interval = currRange[dimToCut][1]-currRange[dimToCut][0];	// interval is always 2^cut
	
	float costs[4], worstCosts[4];
	for(i=0; i<4; i++)	worstCosts[i] = 0;
	
	// decide if current search range really need to cut
	for(num=0; num<numRules; num++)	// how many rules cover the full search range
	{	
		if(ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][0]<=currRange[dimToCut][0] 
			&& ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][1]>=currRange[dimToCut][1])
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
				if(ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][0]>=rangeToSearch[0] 
					&& ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][0]<=rangeToSearch[1])
				{
					smC++;
					costs[0]++;	
				}
				else if(ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][1]>=rangeToSearch[0] 
					&& ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][1]<=rangeToSearch[1])
				{
					smC++;
					costs[0]++; 
				}
				else if(ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][0]<rangeToSearch[0] 
					&& ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][1]>rangeToSearch[1])
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
		
		if(smC<spaceAvailable)
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

int BuildTree(struct TREENODE *rootNode, struct RULESET *ruleSet)
{
	unsigned int num, dim, cut;
	
	// common variables
	unsigned int currRange[4][2] = {{0, 0xffffffff}, {0, 0xffffffff}, {0, 0xffff}, {0, 0xffff}};
	unsigned int currNumRules = ruleSet->numRules;
	unsigned int *currRuleList = (unsigned int*)malloc(currNumRules*sizeof(unsigned int));
	// FAQ: why i allocate so much memory here? --just for convenience.
	
	// initial decision tree
	struct TREENODE *currNode = rootNode;
	currNode->nodeInfo = 0;
	currNode->depth = 1;
	
	// initial chain stack
	struct STACKNODE *stackNode = (STACKNODE *)malloc(sizeof(struct STACKNODE));
	memcpy((unsigned int *)stackNode->currRange, (unsigned int *)currRange, 4*2*sizeof(unsigned int));
	stackNode->numRules = currNumRules;
	stackNode->ruleList = (unsigned int*)malloc(currNumRules*sizeof(unsigned int));
	for(num=0; num<currNumRules; num++)	stackNode->ruleList[num] = num;	// all rules belong to the root node
	stackNode->currTNode = currNode;	
	stackNode->nextNode = NULL;
	struct STACKNODE *prevStackNode;	// for deleting node

	unsigned int	sumDepth=0, worstDepth=0;
	unsigned int	numLeaves =0;
	
	while(TRUE)
	{
		////	pop out a tree node from the stack
		currNode = stackNode->currTNode;
		// update common variables
		currNumRules = stackNode->numRules;
		memcpy((unsigned int *)currRuleList, (unsigned int*)stackNode->ruleList, currNumRules*sizeof(unsigned int));
		memcpy((unsigned int *)currRange, (unsigned int *)stackNode->currRange, 4*2*sizeof(unsigned int));
		// 		printf("\n>>CURRRANGE:");	for(dim=0; dim<4; dim++)	printf("[%x, %x] ", currRange[dim][0], currRange[dim][1]);
// 		printf("\n>>POPOUT:");	for(num=0; num<currNumRules; num++)	printf("%u, ", currRuleList[num]+1);
		// Pop out a node
		prevStackNode = stackNode;
		stackNode = stackNode->nextNode;
		//		if(stackNode!=NULL)
		//			if(prevStackNode->ruleList != stackNode->ruleList)
		//				free(prevStackNode->ruleList);	
		free(prevStackNode);	// delete previouse stack node
		
		////	set rules belong to current node
		if(currNumRules<=BINTH)	// how to treat a leaf node
		{
			currNode->nodeInfo = currNumRules;
			currNode->next = (unsigned int *)malloc(currNumRules*sizeof(unsigned int));
			memcpy((unsigned int*)currNode->next, (unsigned int*)currRuleList, currNumRules*sizeof(unsigned int));

			numLeaves++;
			sumDepth+=currNode->depth;
			gResult.totalMem+=currNumRules*4;
			if(stackNode == NULL)	// no node in stack (the last one is the root node)
			{
				free(currRuleList);	// delete common variables
				// HOW TODO: need to free(stackNode) ???

				gResult.avgDepth = sumDepth/numLeaves;
				gResult.wstDepth = worstDepth;
				return SUCCESS;
			}
		}
		else	// how to treat an internal node...
		{	
			// choose which dimension(field) to cut this time
			struct CUTTING bestCut, tempCut;
			bestCut.costs[0] = (float)currNumRules;
			bestCut.costs[1] = (float)currNumRules;
			for(dim=0; dim<4; dim++)
			{ 
				if(PreCut((unsigned char)dim, currRange, currNumRules, currRuleList, &tempCut, ruleSet) == SUCCESS)
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
			printf("\n>>BESTCUTS: dimCut:%u; numCut:%u; cost:%f", bestCut.dimToCut, bestCut.numCuts, bestCut.costs[0]);
//			printf("\n>>BESTCUTS: dimCut:%u; numCut:%u; cost:%f", bestCut.dimToCut, bestCut.numCuts, bestCut.costs[1]);
			
			// update current tree node
			currNode->dimToCut = bestCut.dimToCut;	currNode->numCuts = bestCut.numCuts;
			unsigned int numCuts = (1<<currNode->numCuts);
			unsigned char dimToCut = currNode->dimToCut;
			currNode->next = (struct TREENODE*)malloc(numCuts*sizeof(struct TREENODE));	// first child
			struct TREENODE *childNodes = (struct TREENODE*)currNode->next;
			// allocate successive memory for children, currNode->next points to his first child
			
			for(cut=0; cut<numCuts; cut++)
				childNodes[cut].depth = currNode->depth+1;
			if(worstDepth<currNode->depth+1)
				worstDepth = currNode->depth+1;
			gResult.totalMem+=numCuts*7;
			gResult.numNodes+=numCuts;
			
			// assign corresponding ruleset for each child tree node
			unsigned int rangeToSearch[2];
			unsigned int tempRange[4][2];
	
	
			// store colliding rules for each child
			unsigned int tempNumRules; // number of rules in each child node
			unsigned int *tempRuleList = (unsigned int *)malloc(currNumRules*sizeof(unsigned int));
			unsigned int preNumRules; // number of rules in previous child node
			unsigned int *preRuleList;
	
			struct STACKNODE *tempStackNode;
			memcpy((unsigned int *)tempRange, (unsigned int *)currRange, 4*2*sizeof(unsigned int));
			
			unsigned int interval = ((currRange[dimToCut][1]-currRange[dimToCut][0])>>currNode->numCuts)+1;
			for(cut=0; cut<numCuts; cut++)
			{
				tempNumRules = 0;
				rangeToSearch[0] = currRange[dimToCut][0]+cut*interval;
				rangeToSearch[1] = rangeToSearch[0]+interval-1;
				for(num=0; num<currNumRules; num++)	
				{	
					if(ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][0]>=rangeToSearch[0] 
						&& ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][0]<=rangeToSearch[1])
					{
						tempNumRules++;
						tempRuleList[tempNumRules-1] = currRuleList[num];
					}
					else if(ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][1]>=rangeToSearch[0] 
						&& ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][1]<=rangeToSearch[1])
					{
						tempNumRules++;
						tempRuleList[tempNumRules-1] = currRuleList[num];
					}
					else if(ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][0]<rangeToSearch[0] 
						&& ruleSet->ruleList[currRuleList[num]].ruleRange[dimToCut][1]>rangeToSearch[1])
					{
						tempNumRules++;
						tempRuleList[tempNumRules-1] = currRuleList[num];
					}
				}
				if(tempNumRules>0)	// if there's any rule collides with this child node
				{
					currNode->nodeInfo = 0;	// no rules collides with this node, except for the defalt rule
					
					tempStackNode = (struct STACKNODE *)malloc(sizeof(struct STACKNODE));	// add a node in stack
					// NOTE: delete this node when it pop out
					tempStackNode->numRules = tempNumRules;
					tempRange[dimToCut][0] = rangeToSearch[0]; tempRange[dimToCut][1] = rangeToSearch[1];
					memcpy((unsigned int *)tempStackNode->currRange, (unsigned int *)tempRange, 4*2*sizeof(unsigned int));
					tempStackNode->currTNode = childNodes+cut;
					tempStackNode->ruleList = (unsigned int *)malloc(tempNumRules*sizeof(unsigned int));
					memcpy((unsigned int*)tempStackNode->ruleList, (unsigned int*)tempRuleList, tempNumRules*sizeof(unsigned int));
					preRuleList = tempStackNode->ruleList;
// 			 		printf("\n>>PUSHIN:");	for(num=0; num<tempNumRules; num++)	printf("%u, ", tempRuleList[num]+1);
					tempStackNode->nextNode = stackNode;
					stackNode = tempStackNode;	
					preNumRules = tempNumRules;
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
	}//while(TRUE)
}


/************************************************************************/
/* functions for classification                                         */
/************************************************************************/
int ReadHeader(FILE *fp, struct PACKETHEADER *header)
{
	char validHeader;// validfilter means an '@'
	unsigned int tpref[4];	// temporary variables to store IP prefix and its lenght
	while (!(feof(fp)))
	{
		fscanf(fp,"%c",&validHeader);
		if (validHeader != '@') continue;	// each header should begin with an '@' 
		
		// reading sIP and dIP
		fscanf(fp,"%d.%d.%d.%d",&tpref[0],&tpref[1],&tpref[2],&tpref[3]);
		header->dim[0] =  (tpref[0] << 24)^(tpref[1] << 16)^(tpref[2] << 8)^(tpref[3]); 
		fscanf(fp,"%d.%d.%d.%d",&tpref[0],&tpref[1],&tpref[2],&tpref[3]);
		header->dim[1] =  (tpref[0] << 24)^(tpref[1] << 16)^(tpref[2] << 8)^(tpref[3]); 
		fscanf(fp,"%d	%d",&header->dim[2], &header->dim[3]);
//		printf("\n>>HEADER: sIP=%x, dIP=%x, sPt=%x, dPt=%x\n", header->dim[0], header->dim[1], header->dim[2], header->dim[3]);
		return SUCCESS;
	}
	return FALSE;
}

int Filtering(struct PACKETHEADER *header, struct TREENODE *rootNode)
{	
	unsigned int i, dim;
	unsigned int currRange[4][2] = {{0, 0xffffffff}, {0, 0xffffffff}, {0, 0xffff}, {0, 0xffff}};// current search space
	unsigned char currCuts[4] = {32, 32, 16, 16};
	unsigned int bias, interval, cuts;
	struct TREENODE *currNode = rootNode;
	unsigned int *ruleList;
	char nodeInfo;
	
	while(TRUE)
	{
		nodeInfo = currNode->nodeInfo;
		if(nodeInfo == 0)	// get an internal nodes
		{
			cuts = (unsigned int)currNode->numCuts;
			dim = (unsigned int)currNode->dimToCut;
			interval = ((currRange[dim][1]-currRange[dim][0])>>cuts)+1;
			currCuts[dim] = currCuts[dim]-cuts;
 			bias = (unsigned int)((header->dim[dim]-currRange[dim][0])>>currCuts[dim]);
			currRange[dim][0] = (unsigned int)(header->dim[dim]>>currCuts[dim])<<currCuts[dim];
			currRange[dim][1] = currRange[dim][0]+interval-1;
			currNode = (struct TREENODE*)currNode->next + bias;
// 			printf("currDim=%u, bias=%u, cuts=%u, nodeInfo=%d\n", dim, bias, cuts, nodeInfo);
//			printf("interval=%x, currRange=[%x, %x], rangewidth=%x\n", interval, currRange[dim][0], currRange[dim][1], currRange[dim][1]-currRange[dim][0]);
		}
		else if(nodeInfo > 0)	// get a common leaf node
		{
			ruleList = (unsigned int*)currNode->next;
			printf("\n>>The packet satisfys:");
			for(i=0; i<(unsigned int)nodeInfo; i++)	printf("%5u ", ruleList[i]+1);
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



	////	LOADING RULES
	printf("\n\n*********************************\n\n");
	printf(">>Loading rules...\n");
	FILE *fp;
	char ruleFile[] = "set0.txt";	// filename of a rule set
	char headerFile[] = "header0.txt";
	fp = fopen(ruleFile,"r");
	if(fp == NULL) 
	{
		printf("ERROR:Couldnt open rule set file \n");
		exit(0);
	}
	struct RULESET ruleSet;
	LoadRules(fp, &ruleSet);	// loading filters...
	fclose(fp);
	printf(">>Number of rules loaded: %d\n",ruleSet.numRules);
	//print each rule
	//	int i, j;
	//	for(j=0; j<4; j++)
	//		for(i=0; i<1; i++)//ruleSet.numRules; i++)
	//			printf("rule%d dim%d: %u~%u\n",i, j, ruleSet.ruleList[i].ruleRange[j][0], ruleSet.ruleList[i].ruleRange[j][1]);
	
	////	BUIDLING DECISION TREE
	struct TREENODE rootNode;	// create rootNode for decision tree
	if(!BuildTree(&rootNode, &ruleSet))
	{
		printf("Something wrong when building our tree...\n");
		exit(0);
	}
	printf("\n>>Finish building the decision tree\n\n");
	// TODO: save the tree in a file

	////	PACKET CLASSIFICATION
	struct PACKETHEADER header;
	fp = fopen(headerFile,"r");
	if(fp==NULL) 
	{
		printf("Couldnt open header file \n");
		exit (0);
	}
	int headerNum=0;
	while(ReadHeader(fp, &header))
	{
		Filtering(&header, &rootNode);
		headerNum++;
	}
	fclose(fp);

	////	RESULTS
	printf("\n>>MEMORY:%u(KB)", gResult.totalMem>>10);
	printf("\n>>DEPTH: %f(average), %u(worstcase)", gResult.avgDepth, gResult.wstDepth);
	printf("\n>>END CLASSIFICATION\n");
	
	
	return 0;
}