// Dynamic cuttings version 5.0 by BabyQi

/************************************************************************/
/* predefination                                                        */
/************************************************************************/
#define TRUE			1
#define FALSE			0
#define ERROR           (-1)
#define SUCCESS         1

#define MAXRULES	5000	// maximum number of rules
#define MAXHEADERS	5000	// maximum number of headers



#define	ALGORITHM		2	// 0, 1, 2 for HiCuts, DCutsQ and DCutsJ
#define SPFAC_ORG		5	// spfac for origal hicuts
#define SPFAC_MAX		5	// optimized for search time
#define SPFAC_AVG		3
#define SPFAC_MIN		2	// optimized for memory usage
#define BINTH			8	// maximum number of rules in leaf nodes

char ruleFile[] = "../data/set4.txt";	// filename of a rule set
char headerFile[] = "../data/header4.txt";

/************************************************************************/
/* structures for filters                                               */
/************************************************************************/
struct RULE						
{
	unsigned int 	pos;	// the position of this filter in classifier 
	unsigned int	ruleRange[4][2];	// the subspace covered by this rule in search space
	// here we use for dimensions: sIP dIP sPt dPt
	// each expressed by ranges
};

struct RULESET
{
	unsigned int	numRules;				// totoal number of rules
	struct RULE		ruleList[MAXRULES];	// rule list, through which we can visit each rule in the classifier
}ruleSet;

/************************************************************************/
/* structures for decision tree                                         */
/************************************************************************/
struct TREENODE	// nodes of decision tree, 7 Bytes
{
	unsigned char	numCuts;	// this is the np(C) in the paper
	unsigned char	dimToCut;	// which dimention to cut
	char			nodeInfo;	// describe different nodes
	// 0 for internal nodes, -1 for non-rule(except for default rules) leaf nodes,  [1, BINTH] for leaf nodes
	
	void	      	*next;		// where to go next step
	//it may be TREENODE* for internal nodes(pointer to next node)
	//or unsigned int* for leaf nodes(pointer to a rule list)

	unsigned int	depth;		// tree depth of this node. do NOT need memory count.
};

struct QUEUENODE // nodes of stack used in building decision tree
{
	unsigned int		currRange[4][2];	// the current search range of each dimention for cutting...
	unsigned int		numRules;			// current number of rules in this node
	float				spfac;				// dynamic spfac
	float				currPv;
	unsigned char		nodeLevel;			// node level in the decision tree
	unsigned int		*ruleList;			// rules colliding with currTNode
	struct TREENODE		*currTNode;			// tree node that needs to cut now
	struct QUEUENODE	*nextNode;			// I am a chain stack...
};

struct QUEUE 
{
	unsigned int		numNodes;			// num of nodes in this level
	float				Pv_max, Pv_min;
 	struct QUEUENODE	*head;
	struct QUEUENODE	*rear;
};

struct CUTTING // describe the results for one cutting
{
	unsigned char numCuts;		// how many cuttings
	unsigned char dimToCut;		// which dim to cut
	float	costs[4];	// different costs for such cuttings
};

/************************************************************************/
/* structures for packet headers                                        */
/************************************************************************/
struct HEADER						
{
	unsigned int	dim[4];		// sIP, dIP, sPort, dPort
};
struct HEADERSET
{
	unsigned int	numHeaders;				// totoal number of rules
	struct HEADER	headerList[MAXHEADERS];	// rule list, through which we can visit each rule in the classifier
}headerSet;

/************************************************************************/
/* structures for space/time comparison                                 */
/************************************************************************/
struct RESULTS
{
	float			avgDepth;
	unsigned int	wstDepth;
	unsigned int    numLeaves;
	unsigned int	numNodes;
	unsigned int	totalMem;
	float			avgSearchTime;
	unsigned int	wstSearchTime;
	unsigned int	numPackets;
}gResult;

/************************************************************************/
/* structures for Network Characteristical Statistics                   */
/************************************************************************/
struct NTS
{
	unsigned int	count[4][65536];
	float			prior[4][65536];
}gNts;
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

/************************************************************************/
/* functions for reading rules                                          */
/************************************************************************/ 
// Load Rule Set into memory
void LoadRules(FILE *fp);
// Read one filter from each line of the filter file, called by LoadFilters(...)
int ReadRules(FILE *fp, unsigned int pos);
// Read ip prefix, called by ReadFilter
void ReadPrefix(FILE *fp, unsigned char* IPpref, unsigned char *IPmask);
// Read port, called by ReadFilter
void ReadPort(FILE *fp, unsigned int *Pt);


/************************************************************************/
/* functions for building decision tree                                 */
/************************************************************************/ 
// Build decision tree, treating current node as root node
int BuildTree(struct TREENODE *rootNode);
// Choose which dimesion to cut this time
int PreCut(unsigned char dimToCut, unsigned int currRange[4][2], unsigned int numRules, float spfac, unsigned int *currRuleList, struct CUTTING *tempCut);
// Load prior distribution of network traffics
int LoadPrior(char dims);

/************************************************************************/
/* functions for classification                                         */
/************************************************************************/
int ReadHeader(FILE *fp, struct HEADER *header);
void LoadHeaders(FILE *fp);
int LinearSearch(unsigned int headerNumber, unsigned int *ruleList, char numRules);
int Filtering(unsigned int headerNumber, struct TREENODE *rootNode);