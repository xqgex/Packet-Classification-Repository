 // function declaration for RFC.CPP

//////////////////////////////////////////////////////////////////////////
// predefination

#define MAXFILTERS	2200	// maximum amount of filters, 1000 for test
#define MAXPACKAGES 1000	// maximum amount of packages, 1000 for test

#define TRUE			1
#define FALSE			0
#define SUCCESS         1
#define LENGTH			32				//length of unsigned int
#define SIZE			69				// SIZE = ceiling ( rules / LENGTH )

//////////////////////////////////////////////////////////////////////////
// datastructure defination 

//	structures for filters...
struct FILTER						
{
	// the bytes needed in practice, totally 
	unsigned int 	cost;				// 4 bytes, 规则的代价, 即规则在规则库中的正序号, 最多允许2^32条规则
	unsigned char  	act;				// 1 byte, 执行命令	
	unsigned int	dim[6][2];			// refer to the start & end of every dimension
};

struct FILTSET
{
	unsigned int	numFilters;				// 规则总数
	struct FILTER	filtArr[MAXFILTERS];	// 存放规则的空间, 这里可以针对规则个数动态分配内存
}filtset;

//	structures for packages...
struct PACKAGE						
{

	unsigned int  	highSIP[2];			// 2 bytes, sIP的高2字节
	unsigned int  	lowSIP[2];			// 2 bytes, sIP的低2字节
	unsigned int  	highDIP[2];			// 2 bytes, dIP的高2字节
	unsigned int  	lowDIP[2];			// 2 bytes, dIP的低2字节
	unsigned int  	sPort;				// 2 bytes, 16位源断口, 这里的16位数占用32位内存
	unsigned int 	dPort;				// 2 bytes, 16位目标端口, 这里的16位数占用32位内存

	unsigned int	dim[6];				// refer to all the dimension
};

struct PACKAGESET
{
	unsigned int	numPackages;				// 网包总数
	struct PACKAGE	PackArr[MAXPACKAGES];		// 存放网包的空间, 这里可以针对网包个数动态分配内存
}packageset;

// structure for CES...
typedef struct CES
{
	unsigned short eqID;				// 2 byte, eqID;
	unsigned int  cbm[SIZE];			// LENGTH×SIZE bits, CBM
	CES *next;							// next CES
}CES;

// structure for List of CES
typedef struct LISTEqS
{
	unsigned short nCES;					// number of CES
	CES *head;							// head pointer of LISTEqS 
	CES *rear;							// pointer to end node of LISTEqS
}LISTEqS;

// structure for Phase0 node
typedef struct PNODE
{
	unsigned short cell[65536];			// each cell stores an eqID
	LISTEqS listEqs;					// list of Eqs
}Pnode;

// structure for Phase1 & Phase2 node
typedef struct PNODER
{
	unsigned int ncells;
	unsigned short *cell;				// dynamic alloc
	LISTEqS listEqs;
}Pnoder;

// structure for Phase 0
Pnode phase0_Nodes[6];

// structure for Phase 1
Pnoder phase1_Nodes[2];

// structure for Phase 2
Pnoder phase2_Node;

// structure for lookup result
unsigned short *lookupResult;

// Find proper order to cut memory occupied
unsigned int dot[6];


//////////////////////////////////////////////////////////////////////////
// function declaration

// Load Filter Set into memory
void LoadFilters(FILE *fp, FILTSET * filtset);

// Load Package Set into memory
void LoadPackages(FILE *fp, PACKAGESET * packageset);

// Read one filter from each line of the filter file, called by LoadFilters(...)
int ReadFilter(FILE *fp, FILTSET * filtset,	unsigned int cost);

// Read ip IP range, called by ReadFilter
void ReadIPRange(FILE *fp,unsigned int* highRange,unsigned int* lowRange);

// Read port, called by ReadFilter
void ReadPort(FILE *fp, unsigned int *from, unsigned int *to);

// Read protocol, called by ReadFilter
void ReadProtocol(FILE *fp, unsigned char *from, unsigned char *to);

// Load Filters from file, called by main
void ReadFilterFile();

// Check the result of the loaded filters, called by main
void CheckData();

// Function to set bit value (0 or 1), called by SetPhase0_Cell
void SetBmpBit(unsigned int *tbmp,unsigned int i, bool value);


// Initialize listEqs, called by SetPhase0_Cell
void InitListEqs(LISTEqS *ptrlistEqs);

// Compare two bmp, called by SearchBmp
bool CompareBmp(unsigned int *abmp, unsigned int *bbmp);

// Function to search bmp in listEqs, called by SetPhase0_Cell
int SearchBmp(LISTEqS *ptrlistEqs,unsigned int *tbmp);

// Add new CES to ListEqs, called by SetPhase0_Cell
int AddListEqsCES(LISTEqS *ptrlistEqs,unsigned int *tbmp);

// Get rule cost number with highest priority, called by SetPhase2_Cell
unsigned int GetRuleCost(unsigned int *tbmp);

// Free listEqs space, called by SetPhase1_Cell() & SetPhase2_Cell()
void FreeListEqs(LISTEqS *ptrlistEqs);

// Function to fill the table of Phase 0
void SetPhase0_Cell();

// Find proper order to cut memory occupied
// Set number in dot[6]
void FindOrder();

// Function to fill the table of Phase 1
void SetPhase1_Cell();

// Function to fill the table of Phase 2
void SetPhase2_Cell();

// Lookup, called by main
// the packages are in packageset.txt
// Result: save into lookupResult.txt
void Lookup();

// count memory : memory occupied by chunks
void CountMemory();

// save preprocessing result to chunkdata.txt
void SaveChunks();

// load preprocessing result from chunkdata.txt
void LoadChunks();

// preprocessing according to filterset
// Aim : To establish the chunks & save to file chunkdata.txt
void Preprocess();
