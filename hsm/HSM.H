 // function declaration for HSM.CPP

//////////////////////////////////////////////////////////////////////////
// predefination

#define MAXFILTERS	2200	// maximum amount of filters, 1000 for test
#define MAXPACKAGES 1000	// maximum amount of packages, 1000 for test

#define LENGTH		32		//length of unsigned int
#define SIZE		69		// SIZE = ceiling ( rules / LENGTH )

#define TRUE			1
#define FALSE			0
#define SUCCESS         1

//////////////////////////////////////////////////////////////////////////
// datastructure defination 

//	structures for filters...
struct FILTER						
{
	unsigned int cost;						// 规则序号 (优先级)
	unsigned int dim[4][2];					// refer to the 4 ranges above
	unsigned char act;						// 执行操作 (接收 or 拒绝)
};

struct FILTSET
{
	unsigned int	numFilters;				// 规则总数
	struct FILTER	filtArr[MAXFILTERS];	// 存放规则的空间, 这里可以针对规则个数动态分配内存
}filtset;

//	structures for packages...
struct PACKAGE						
{
	unsigned int  	SIP;			
	unsigned int  	DIP;
	unsigned int  	sPort;				
	unsigned int 	dPort;				
	unsigned int	dim[4];				// refer to all the dimension
};

struct PACKAGESET
{
	unsigned int	numPackages;				// 网包总数
	struct PACKAGE	PackArr[MAXPACKAGES];		// 存放网包的空间, 这里可以针对网包个数动态分配内存
}packageset;

// structure for filter rule start & end points
struct TPOINT
{
	unsigned int value;						// start or end point value
	unsigned char flag;						// indicate start or end
											// 1 ~ start ;  2 ~ end
};

typedef struct TPOINT * ptrPoint;
ptrPoint ptrfiltsetdim[4];

// structure for fragmentation range used for generate array structure
// use linklist structure
// Aim : to create the array used for lookup
// when lookup array is created, this will be released
struct FRAGNODE
{
	unsigned int start;
	unsigned int end;
	struct FRAGNODE *next;
};

struct FRAGLINKLIST
{
	unsigned int fragNum;
	struct FRAGNODE *head;
};

typedef struct FRAGLINKLIST * ptrFragLinklist;

// structure for fragmentation range used for lookup
// use array structure
struct TFRAG
{
	unsigned int start;						// start point
	unsigned int end;						// end point
	unsigned int cbm[SIZE];					// LENGTH * SIZE bits, CBM
};
typedef struct TFRAG * ptrTFrag;
ptrTFrag ptrTfrag[4];						// released after tMT[2] is generated

struct FRAG
{
	unsigned int start;
	unsigned int end;
};
typedef struct FRAG * ptrFrag;
ptrFrag ptrfrag[4];							// the Array used for lookup
unsigned int fragNum[4];					// the frag numbers of the arrays
int dot[4];									// used for arrange ptrfrag[0]~ptrfrag[4]

// structure for CES...
typedef struct CES
{
	unsigned short eqID;					// 2 byte, eqID;
	unsigned int  cbm[SIZE];				// LENGTH×SIZE bits, CBM
	CES *next;								// next CES
}CES;

// structure for List of CES
struct LISTEqS
{
	unsigned short nCES;					// number of CES
	CES *head;								// head pointer of LISTEqS 
	CES *rear;								// pointer to end node of LISTEqS
};
typedef struct LISTEqS *ptrLISTEqS;
ptrLISTEqS listEqs[2];

// structure for AMT & PMT
unsigned int *MT[2];						// MT[0] ~ AMT		MT[1] ~ PMT

// structure for PLT
unsigned int *PLT;

//////////////////////////////////////////////////////////////////////////
// function declaration

// Load Filter Set into memory
void LoadFilters(FILE *fp, FILTSET * filtset);

// Load packages
void LoadPackages(FILE *fp, PACKAGESET packageset);

// Read one filter from each line of the filter file, called by LoadFilters(...)
int ReadFilter(FILE *fp, FILTSET * filtset,	unsigned int cost);

// Read ip IP range, called by ReadFilter
void ReadIPRange(FILE *fp,unsigned int* IPrange);

// Read port, called by ReadFilter
void ReadPort(FILE *fp, unsigned int *from, unsigned int *to);

// Load Filters from file, called by main
void ReadFilterFile();

// Read filtset dimension range into dynamic array, called by main
void CreatePointArray();

// Sort points by value, called by  CreatePointArray
// when value is equal, make sure point whose flag equals 1 ranks in advance
void SortPoints(ptrPoint pPoint, unsigned int num);

// set the bit referring to a rule	( 0 or 1 ), called by CreateFragArray
void SetBmpBit(unsigned int *tbmp,unsigned int i, bool value);

// Compare two bmp, called by CreateFragArray
bool CompareBmp(unsigned int *abmp, unsigned int *bbmp);

// Create dimension fragmentation array used for lookup, called by main
void CreateFragArray();

// Initialize listEqs, called by SetPhase0_Cell
void InitListEqs(LISTEqS *ptrlistEqs);

// Function to search bmp in listEqs, called by CreateMapTable
int SearchBmp(LISTEqS *ptrlistEqs,unsigned int *tbmp);

// Add new CES to ListEqs, called by CreateMapTable
int AddListEqsCES(LISTEqS *ptrlistEqs,unsigned int *tbmp);

// Locate CES by eqID in listEqs
CES *LocateCES(ptrLISTEqS listEqs,unsigned short ID);

// Create AMT & PMT, called by main
void CreateMapTable();

// Find order of ptrfrag[4] by size
void FindOrder();

// Get rule cost number with highest priority, called by CreatePLT
unsigned int GetRuleCost(unsigned int *tbmp);

// Free listEqs, called by CreatePLT
void FreeListEqs(LISTEqS *ptrlistEqs);

// Create PLT, called by main
void CreatePLT();

// Lookup, called by main
void Lookup();

// Search segment id, called by Lookup
unsigned int SearchSegID(ptrFrag pfrag,unsigned int tfragNum,unsigned int value);

// Count memory used 
void CountMemory();