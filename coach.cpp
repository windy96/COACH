 /*
 *	COACH
 *	COherence Analyzer and CHecker tool for Programmer Managed Cache
 *
 *	Description
 *		This program helps programmers to write programs for software-managed cache coherence
 *		even on the machine with hardware-managed cache coherence.
 *		COACH reports cache coherence violations at synchronization boundaries
 *		and shows where the program makes violations.
 *		COACH also suggests possible performance enhancements for more efficient codes.
 *
 *	Programming
 *		started from Jun 3, 2012
 *		last updated on Apr 3, 2013
 *		written by Kim, Wooil
 *		kim844@illinois.edu
 *
 */


#include "pin.H"
#include "stdio.h"
#include "string.h"
#include <string>
#include <map>
#include <vector>
#include <list>
#include <bitset>
#include <set>
#include <bits/wordsize.h>


//-------------------------------------------------------------------
//	Configurable Parameters
//-------------------------------------------------------------------

//	Maximum worker threads are set to 32.
#define MAX_WORKER	32
//	Maximum threads are maximum work threads + 1 to support master-workers execution model.
#define MAX_THREADS MAX_WORKER+1
#define STATE_BITS	3
#define MAX_STATES  (MAX_THREADS)*(STATE_BITS)

#define WORD_BITWIDTH	32
#define WORD_BYTES		4

const char *configFileName = "coach.cfg";




//	Currently all operations are verified with 64-bit only.
//	[TODO] make this work with 32-bit binaries
#if __WORDSIZE == 64
	#define INT_SIZE	8
	#define WORD_SIZE	4
	#define ADDR_MASK	0xFFFFFFFFFFFFFFFC
#else
	// 32-bit execution is not verified yet.
	#define INT_SIZE	4
	#define WORD_SIZE	4
	#define ADDR_MASK	0xFFFFFFFC
#endif

//	[TODO] this will be deleted.
#define LINE_SIZE	64
#define PAD_SIZE 	(LINE_SIZE - INT_SIZE)


using namespace std;



//-------------------------------------------------------------------
//	Logger
//-------------------------------------------------------------------

//	WindyLogger is used for displaying all logging/debugging/error messages.
//	It has five display levels, and can have output file other than stdout.
class WindyLogger
{
private:
	int		displayLevel;
	int		fileoutLevel;
	FILE*	outputFile;

public:
	enum DisplayLevelEnum {
		DISPLAY_TEMP_DEBUG,		// Debugging information which will be used temporarily.
		DISPLAY_DEBUG,
		DISPLAY_LOG,
		DISPLAY_WARNING,
		DISPLAY_ERROR,
		DISPLAY_NONE			// At this level, any message is not displayed.
	};

	enum FileoutLevelEnum {
		FILEOUT_TEMP_DEBUG,		// Debugging information which will be used temporarily.
		FILEOUT_DEBUG,
		FILEOUT_LOG,
		FILEOUT_WARNING,
		FILEOUT_ERROR,
		FILEOUT_NONE			// At this level, any message is not displayed.
	};

	WindyLogger() 
	{ 
		displayLevel = DISPLAY_ERROR;
		fileoutLevel = FILEOUT_LOG;
		outputFile = stdout;
	}

	int		getDisplayLevel()		{ return displayLevel; }
	void	setDisplayLevel(int d)	{ displayLevel = d; }

	int		getFileoutLevel()		{ return fileoutLevel; }
	void	setFileoutLevel(int d)	{ fileoutLevel = d; }

	FILE*	getOutputFile()			{ return outputFile; }
	void	setOutputFile(FILE* fp)	{ outputFile = fp; }
	void	close()					{ fprintf(outputFile, "#eof\n"); fclose(outputFile); }


	void temp(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_TEMP_DEBUG) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[TEMP]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_TEMP_DEBUG) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[TEMP]  ");
			va_start(args, format);
			vfprintf(outputFile, format, args);
			va_end(args);
			fprintf(outputFile, "\n");
		}
	}

	void debug(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_DEBUG) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[DEBUG]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_DEBUG) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[DEBUG]  ");
			va_start(args, format);
			vfprintf(outputFile, format, args);
			va_end(args);
			fprintf(outputFile, "\n");
		}
	}

	void log(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_LOG) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[LOG]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_LOG) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[LOG]  ");
			va_start(args, format);
			vfprintf(outputFile, format, args);
			va_end(args);
			fprintf(outputFile, "\n");
		}
	}

	void warn(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_WARNING) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[WARN]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_WARNING) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[WARN]  ");
			va_start(args, format);
			vfprintf(outputFile, format, args);
			va_end(args);
			fprintf(outputFile, "\n");
		}
	}

	void error(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_ERROR) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[ERROR]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_ERROR) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[ERROR]  ");
			va_start(args, format);
			vfprintf(outputFile, format, args);
			va_end(args);
			fprintf(outputFile, "\n");
		}
	}

};	// class WindyLogger

WindyLogger		Logger;



//-------------------------------------------------------------------
//	Data Structure
//-------------------------------------------------------------------

//	sourceLocation structure is used in MallocTracker.
//	This structure is used for storing source code location.
struct sourceLocation
{
	int		col;
	int		line;
	string	filename;

	sourceLocation() {}
	sourceLocation(int c, int l, string fname)
		: col(c), line(l), filename(fname)
	{ }
};


//	Memory Allocation Tracker
class MallocTracker 
{
private:
	// Address and size pair is maintained in STL map.
	map<ADDRINT, int>			addrMap;
	map<ADDRINT, int>::iterator	it;

	map<ADDRINT, struct sourceLocation>				sourceMap;
	map<ADDRINT, struct sourceLocation>::iterator	sourceIt;

	map<ADDRINT, string>			variableNameMap;
	map<ADDRINT, string>::iterator	variableNameIt;

	map<ADDRINT, bitset<MAX_STATES>* >				stateMap;
	map<ADDRINT, bitset<MAX_STATES>* >::iterator	stateIt;

public:
	//	Previous information about allocation is open for WritesMemBefore.
	ADDRINT		prevAddr;
	int			prevSize;

	MallocTracker() 
	{ 
		addrMap.clear(); 
		sourceMap.clear();
		prevAddr = 0;
		prevSize = 0;
	}

	bool hasEntry(ADDRINT addr) { return (addrMap.find(addr) != addrMap.end()); }

	void add(ADDRINT addr, int size) 
	{
		// if we already have the same address as a start address, this is problematic.
		// sometimes the program exectues malloc twice for some reason, this should not be treated as errors.
		if (hasEntry(addr)) {
			if (addrMap[addr] != size) {
				Logger.warn("Memory allocation occurs for the already allocated address: 0x%lx.", addr);
				return;
			}

			// memory allocation for the same address and size is called.
			// For now, just ignore it.
			// calloc after malloc initializes the value. Thus, if we consider the value, we should check it.
			return;
		}

		addrMap[addr] = size;
		prevAddr = addr;
		prevSize = size;

		// [TODO] consider word-alignment
		// Currently, only word-aligned memory allocation is considered.
		bitset<MAX_STATES>	*pState;
		int wordSize = (size+3) / 4;
		pState = new bitset<MAX_STATES> [wordSize];
		for (int i = 0; i < wordSize; i++)
			pState[i].reset();
		stateMap[addr] = pState;
		Logger.log("Memory is allocated for addr 0x%lx with size 0x%x.", addr, size);
	}

	void remove(ADDRINT addr) 
	{
		// free(ptr) removes the entry.

		// If address is 0, this may be free(ptr) call from the system.
		// We ignore this.
		if (addr == 0)
			return;

		// If the address is not in addrMap, this might be a problem.
		// For now, however, this is not our concern.
		if (!hasEntry(addr))
			return;

		Logger.log("Memory is freed for addr 0x%lx with size 0x%x.", addr, addrMap[addr]);
		delete[] (stateMap[addr]);
		stateMap.erase(addr);
		addrMap.erase(addr);
	}

	// to check if addr is within currently allocated memory area
	bool contain(ADDRINT addr)
	{
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			ADDRINT	startAddr, endAddr;

			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					return true;
			}
			else
				return false;
		}
		return false;
	}

	// to provide an offset inside the variable for the given address
	// It is recommended to call getOffset with true return value of contain.
	ADDRINT getOffset(ADDRINT addr)
	{
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			ADDRINT	startAddr, endAddr;

			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					return addr - startAddr;
			}
			else
				return -1;
		}
		return -1;
	}

	bitset<MAX_STATES>* bitVector(ADDRINT addr)
	{
		ADDRINT	startAddr, endAddr;

		startAddr = 0;	// this is for turning off warning message.
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					break;
			}
			else {
				Logger.error("No match in bitVector for address 0x%lx (overrun): saddr 0x%lx, eaddr 0x%lx.", addr, startAddr, endAddr);
				return NULL;
			}
		}
		if (it == addrMap.end()) {
			Logger.error("No match in bitVector for address 0x%lx (end).", addr);
			return NULL;
		}

		return &( ( (stateMap[startAddr]) )[(addr - startAddr) / 4] );
	}


	// Source functions are doing the same thing as above functions, 
	// but this is for maintaining source code location.
	void addSource(int column, int line, string filename)
	{
		sourceMap[prevAddr] = sourceLocation(column, line, filename);
	}

	void removeSource(ADDRINT addr)
	{
		sourceMap.erase(addr);
	} 

	struct sourceLocation* getSource(ADDRINT addr)
	{
		ADDRINT	startAddr, endAddr;

		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					break;
			}
			else {
				Logger.error("No match in getSource for address 0x%lx (overrun): saddr 0x%lx, eaddr 0x%lx.", addr, startAddr, endAddr);
				return NULL;
			}
		}
		if (it == addrMap.end()) {
			Logger.error("No match in getSource for address 0x%lx (end).", addr);
			return NULL;
		}
		
		return &(sourceMap[startAddr]);
	}


	// Variable name functions are doing the same thing as above functions, 
	// but this is for maintaining variable names for memory allocation.
	void addVariableName(string s, int offset)
	{
		if (offset != 0) {
			char	t[10];
			sprintf(t, "[%d]", offset);
			s.append(t);
		}

		Logger.temp("addVariableName: %s is added as addr 0x%lx.", s.c_str(), prevAddr);
		variableNameMap[prevAddr] = s;
	}

	void removeVariableName(ADDRINT addr)
	{
		variableNameMap.erase(addr);
	}

	string getVariableName(ADDRINT addr)
	{
		ADDRINT	startAddr, endAddr;

		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					break;
			}
			else {
				Logger.error("No match in getVariableName for address 0x%lx (overrun): saddr 0x%lx, eaddr 0x%lx.", addr, startAddr, endAddr);
				return NULL;
			}
		}
		if (it == addrMap.end()) {
			Logger.error("No match in getVariableName for address 0x%lx (end).", addr);
			return NULL;
		}
		
		return variableNameMap[startAddr];		
	}
};	// class MallocTracker


//	This structure is used for thread-specific read/write counts.
//	pad is used to avoid per-thread cache invalidation.  Line size is assumed as 64-Bytes.
struct thread_data_t
{
	UINT64	count;
	UINT8	pad[PAD_SIZE];
};



//	Global variable information is stored in this structure.
struct GlobalVariableStruct {
	string	name;
	ADDRINT	addr;
	int		size;
	ADDRINT	allocAddr;		// if this variable is used for memory allocation, allocated address in heap is registered here.
	int		allocSize;
	bitset<MAX_STATES>	*pState;

	GlobalVariableStruct() { }
	GlobalVariableStruct(string s, ADDRINT a, int sz, int aa, int as)
		: name(s), addr(a), size(sz), allocAddr(aa), allocSize(as)
	{
		// [TODO] here, I do not consider word alignment.
		int wordSize = (sz+3) / 4;
		pState = new bitset<MAX_STATES> [wordSize];
		for (int i = 0; i < wordSize; i++)
			pState[i].reset();
	}

	void attachState()
	{
		int wordSize = (allocSize + 3) / 4;
		pState = new bitset<MAX_STATES> [wordSize];
		for (int i = 0; i < wordSize; i++)
			pState[i].reset();
	}
};


//	Global variable information is stored in this structure.
struct GlobalVariableStruct2 {
	string	name;
	ADDRINT	addr;
	int		size;
	ADDRINT	allocAddr;		// if this variable is used for memory allocation, allocated address in heap is registered here.
	int		allocSize;

	char	*pState[MAX_THREADS];

	GlobalVariableStruct2() { }
	GlobalVariableStruct2(string s, ADDRINT a, int sz, int aa, int as)
		: name(s), addr(a), size(sz), allocAddr(aa), allocSize(as)
	{
		// [TODO] need to check global variable is always aligned.
		// I consider global variable is aligned properly.
		int wordSize = (sz+(WORD_BYTES-1)) / WORD_BYTES;	// i.e. (sz + 3) / 4
		pState[0] = new char [wordSize];
		memset(pState[0], 0, wordSize);
	}

	// attachState is called by malloc routine.
	void attachState()
	{
		int wordSize = (allocSize+(WORD_BYTES-1)) / WORD_BYTES;	// i.e. (sz + 3) / 4
		pState[0] = new char [wordSize];
		memset(pState[0], 0, wordSize);
	}
};


//	Code for PMC instructions
enum PMCInst {
	invalidation,
	writeback,
	writebackInvalidation,
	loadBypass,
	storeBypass,
	writebackMerge,
	writebackReserve,
	writeFirst
};

enum ProgramCategory {
	UNKNOWN,
	PTHREAD,
	GTHREAD,
	OPENMP
};



//-------------------------------------------------------------------
//	Global Variables
//-------------------------------------------------------------------

//	Category configuration
int				Category;

//	Display configuration
BOOL			Suggestion;
char			OutputFileName[100];
FILE			*OutputFile;

// Machine configuration
int				MaxWorkerThreads;
int				CacheLineSize;

// variable configuration
char			VariableFileName[100];
BOOL			ExcludePotentialSystemVariables;	// if true, global variable which name starts with '.' or '_' is ignored.

//	tracking configuration
BOOL			AfterMainTracking;			// if true, address tracking is enabled after main function is started
BOOL			MainRunning;				// after main function is started, this is set as true.
BOOL			MasterThreadOnlyAllocFree;	// if true, memory allocation/free from child threads is not tracked



PIN_LOCK		Lock;

INT				NumThreads;					// Current number of threads
INT				MaxThreads;					// Maximum number of threads appeared during execution
UINT			BarrierCount;				// How many barrier region appeared
INT				BarrierNumber;				// How many participants for this barrier
INT				CurrentBarrierArrival;		// For tracking currently arrived participants for the barrier
MallocTracker	MATracker;

std::map<ADDRINT, std::string>	DisAssemblyMap;
struct thread_data_t	NumReads[MAX_THREADS];
struct thread_data_t	NumWrites[MAX_THREADS];

BOOL			AfterAlloc[MAX_THREADS];	// if true, it is just after memory allocation function.

//list<ADDRINT>	WrittenWordsInPrevEpoch[MAX_THREADS];
set<ADDRINT>	WrittenWordsInPrevEpoch[MAX_THREADS];
//list<ADDRINT>	WrittenWordsInThisEpoch[MAX_THREADS];
set<ADDRINT>	WrittenWordsInThisEpoch[MAX_THREADS];
//list<ADDRINT>::iterator	WrittenWordsIterator[MAX_THREADS];
set<ADDRINT>::iterator	WrittenWordsIterator[MAX_THREADS];

map<ADDRINT, int> WrittenBackInThisEpoch[MAX_THREADS];
map<ADDRINT, int>::iterator WrittenBackIterator[MAX_THREADS];


//	Global Variable Vector
//	State definition
//	00 means unloaded state
//	01 means valid state
//	10 means stale state
vector<struct GlobalVariableStruct>	GlobalVariableVec;
vector<struct GlobalVariableStruct>::iterator	GlobalVariableVecIterator;

//	This is not enough for tracking many lock variables.
//	For only checking single lock variable, MutexLocked is used.
BOOL			MutexLocked;

//list<ADDRINT>	WrittenWordsInThisLock[MAX_THREADS];
set<ADDRINT>	WrittenWordsInThisLock[MAX_THREADS];
map<ADDRINT, int> WrittenBackInThisLock[MAX_THREADS];




//-------------------------------------------------------------------
//	Global Functions
//-------------------------------------------------------------------

void AnalyzeWritebacksAcrossThreads();
void AnalyzeBarrierRegion(int tid);
void CheckBarrierResultBefore(THREADID tid);
void CheckBarrierResultBeforeGOMPImplicit(THREADID tid);


//	Check if given address is for global variable
BOOL isGlobalVariable(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			return true;
		if ( (addr >= (*it).addr) && (addr < (*it).addr + (*it).size) )
			return true;
	}
	return false;
}


//	Calculate the offset within global variable
//	The address should be for global variable. If not, -1 will be returned.
ADDRINT offsetInGlobalVariable(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			return 0;
		if ( (addr >= (*it).addr) && (addr < (*it).addr + (*it).size) )
			return (addr - (*it).addr);
	}
	// This must not happen.
	return -1;
}


bitset<MAX_STATES>* bitVectorForGlobalVariable(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			return &((*it).pState[0]);
		if ( (addr >= (*it).addr) && (addr < (*it).addr + (*it).size) )
			return &((*it).pState[(addr-(*it).addr) / 4]);
	}

	Logger.error("No match in bitVectorForGlobalVariable (end or overrun) addr = 0x%lx", addr);
	Logger.error("List of global variables");
	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		Logger.error("addr=0x%lx, size=%d", (*it).addr, (*it).size);
	}

	return NULL;
}


const char* getGlobalVariableName(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			return (*it).name.c_str();
		if ( (addr >= (*it).addr) && (addr < (*it).addr + (*it).size) )
			return (*it).name.c_str();
	}

	Logger.error("No match in getGlobalVariableName (end or overrun) addr = 0x%lx", addr);
	return NULL;
}


//-------------------------------------------------------------------
//	Functions for Instruction Instrumentation
//-------------------------------------------------------------------

//	Generic Function Call Tracker
VOID FuncBefore(THREADID tid, CHAR *name, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] func %s is called. (%s in %s)\n", tid, name, rtnName, secName);
	ReleaseLock(&Lock);
}


VOID FuncArg1IntBefore(THREADID tid, CHAR *name, INT arg1, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] func %s with arg %d is called. (%s in %s)\n", tid, name, arg1, rtnName, secName);
	ReleaseLock(&Lock);
}


VOID FuncArg1AddrBefore(THREADID tid, CHAR *name, ADDRINT arg1, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] func %s with arg 0x%lx is called. (%s in %s)\n", tid, name, arg1, rtnName, secName);
	ReleaseLock(&Lock);
}


VOID FuncArg2IntIntBefore(THREADID tid, CHAR *name, INT arg1, INT arg2, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] func %s with arg %d, %d is called. (%s in %s)\n", tid, name, arg1, arg2, rtnName, secName);
	ReleaseLock(&Lock);
}


VOID FuncArg2AddrIntBefore(THREADID tid, CHAR *name, ADDRINT arg1, INT arg2, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] func %s with arg 0x%lx, %d is called. (%s in %s)\n", tid, name, arg1, arg2, rtnName, secName);
	ReleaseLock(&Lock);
}


VOID FuncAfter(THREADID tid, CHAR *name)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d]   func %s is returned.\n", tid, name);
	ReleaseLock(&Lock);
}


VOID FuncRetIntAfter(THREADID tid, CHAR *name, INT ret)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d]   func %s with return value %d is returned.\n", tid, name, ret);
	ReleaseLock(&Lock);
}


VOID FuncRetAddrAfter(THREADID tid, CHAR *name, ADDRINT ret)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d]   func %s with return value 0x%lx is returned.\n", tid, name, ret);
	ReleaseLock(&Lock);
}


//	Special Function Call Tracker
//	This is used for main function.
VOID SpecialBefore(THREADID tid, CHAR *name, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] *** %s is called. (%s in %s)\n", tid, name, rtnName, secName);
	MainRunning = true;
	ReleaseLock(&Lock);
}


VOID SpecialAfter(THREADID tid, CHAR *name, INT ret)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] *** %s with return value %d is returned.\n", tid, name, ret);
	MainRunning = false;
	ReleaseLock(&Lock);
}


//	Wrappers for Memory Allocation
VOID* vallocWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, int size)
{
	VOID *ret;
	CONTEXT writableContext, * context = ctxt;

	/*
	if (TimeForRegChange()) {
		PIN_SaveContext(ctxt, &writableContext); // need to copy the ctxt into a writable context
		context = & writableContext;
		PIN_SetContextReg(context , REG_GAX, 1);
	}
	*/

	PIN_CallApplicationFunction(context, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		//	PIN_PARG(VOID *), v,
		PIN_PARG(int), size,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] valloc with size 0x%x returns 0x%lx.\n", tid, size, (ADDRINT) ret);

	// if return value is NULL, valloc failed. address is not tracked, then.
	if (ret != NULL)
		MATracker.add((ADDRINT) ret, size);
	else
		Logger.warn("[tid: %d] valloc failed.", tid);
	AfterAlloc[tid] = true;
	
	ReleaseLock(&Lock);
	return ret;
}


VOID* mallocWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, int size)
{
	VOID *ret;

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		//	PIN_PARG(VOID *), v,
		PIN_PARG(int), size,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] malloc with size 0x%x returns 0x%lx\n", tid, size, (ADDRINT) ret);

	// if return value is NULL, malloc failed. address is not tracked, then.
	if (ret != NULL)
		MATracker.add((ADDRINT) ret, size);
	else
		Logger.warn("[tid: %d] valloc failed.", tid);
	AfterAlloc[tid] = true;
	
	ReleaseLock(&Lock);
	return ret;
}


VOID* callocWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, int nmeb, int size)
{
	VOID *ret;

	Logger.warn("[tid: %d] calloc is called with nmeb %d and size %d, but wrapper function for calloc is not verified yet.", tid, nmeb, size);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		//	PIN_PARG(VOID *), v,
		PIN_PARG(int), nmeb,
		PIN_PARG(int), size,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] calloc with nmeb %d, size %d returns 0x%lx\n", tid, nmeb, size, (ADDRINT) ret);

	// [TODO] This is not verified.
	// calloc allocates the memory as nmeb*size, however memory alignment should be considered.
	// if return value is NULL, valloc failed. address is not tracked, then.
	if (ret != NULL)
		MATracker.add((ADDRINT) ret, nmeb*size);
	else
		Logger.warn("[tid: %d] calloc failed.", tid);
	AfterAlloc[tid] = true;

	ReleaseLock(&Lock);
	return ret;
}


VOID* reallocWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID *ptr, int size)
{
	VOID *ret;

	Logger.warn("[tid: %d] realloc is called for 0x%p, but not supported completely for now.", tid, ptr);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), ptr,
		PIN_PARG(int), size,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] realloc with ptr 0x%p, size %d returns 0x%lx\n", tid, ptr, size, (ADDRINT) ret);

	// if return value is NULL, realloc failed. address is not tracked, then.
	if (ret != NULL) {

		// if ptr is null, realloc is the same as malloc.
		// even if ptr is null, we have safety in AddrMap, so remove is called.
		MATracker.remove((ADDRINT) ptr);
		// if the size is 0, it is equal to free(ptr).
		if (size > 0)
			MATracker.add((ADDRINT) ret, size);
	}
	else
		Logger.warn("[tid: %d] realloc failed.", tid);
	AfterAlloc[tid] = true;

	ReleaseLock(&Lock);
	return ret;
}



VOID* posix_memalignWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, int size)
{
	VOID *ret;

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		//	PIN_PARG(VOID *), v,
		PIN_PARG(int), size,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] posix_memalign with size 0x%x returns 0x%lx\n", tid, size, (ADDRINT) ret);

	// if return value is NULL, posix_memalign failed. address is not tracked, then.
	if (ret != NULL)
		MATracker.add((ADDRINT) ret, size);
	else
		Logger.warn("[tid: %d] posix_memalign failed.", tid);
	AfterAlloc[tid] = true;
	
	ReleaseLock(&Lock);
	return ret;
}


VOID* freeWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID *ptr)
{
	VOID *ret;

	/* 
	// for debug
	GetLock(&Lock, tid+1);
	fprintf(Trace, "[tid: %d] before free with ptr %p.\n", tid, ptr);
	fflush(Trace);
	ReleaseLock(&Lock);
	*/
	//Logger.log("[tid: %d] free is called for %p, but not removed from allocation tracker for now.", tid, ptr);
	
	// eagerly removed allocated objects before free call.
	// because it is observed that during free time, some wierd writes appeared to the freeing memory region.
	/*
	// removing from MATracker is not executed for now. 
	// When memory is freed, written result loses where to find its source.
	// for FFT, this happens with -p4 options, resuling in overrun of MATracker with pthread related area.
	if (MainRunning) {
		if ((MasterThreadOnlyAllocFree && (tid == 0)) || !MasterThreadOnlyAllocFree) {
			GetLock(&Lock, tid+1);
			MATracker.remove((ADDRINT) ptr);
			ReleaseLock(&Lock);
		}
	}
	*/

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), ptr,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] free with ptr 0x%p returns.\n", tid, ptr);

	// remove call is moved forward to prevent some wierd writes during free() call.
	// MATracker.remove((ADDRINT) ptr);
	ReleaseLock(&Lock);

	return ret;
}


//---------------------------------------------------------
// PMC Functions
//---------------------------------------------------------

VOID ReadsMemBefore (ADDRINT applicationIp, THREADID tid, ADDRINT memoryAddressRead, UINT32 memoryReadSize);
VOID WritesMemBefore(ADDRINT applicationIp, THREADID tid, ADDRINT memoryAddressWrite, UINT32 memoryWriteSize);



void PMC_process(PMCInst function, int tid, ADDRINT addr, int size)
{
	ADDRINT startWordAddress, endWordAddress, offset;
	ADDRINT offsetMask = 0x3;					// WORD_SIZE - 1;

	startWordAddress = addr & ADDR_MASK;
	endWordAddress = (addr + size) & ADDR_MASK;
	offset = addr & offsetMask;

	for (ADDRINT a = startWordAddress; a + offset < endWordAddress; a += WORD_SIZE)
	{
		switch (function) {
		case invalidation:
			// Since invalidation is not related to written words,
			// so far there is nothing to do.
			// [TODO] invalidation should be recorded to check
			// 1) if this is for previously written word,
			// 2) if this invalidated word is read
			break; //LC[tid].removeEntry(a); break;

		case writeback:
			// When the word is written back, it is removed from written word list.
			Logger.temp("writeback starts.");

			/*
			for (WrittenWordsIterator[tid] = WrittenWordsInThisEpoch[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end(); WrittenWordsIterator[tid]++)
			{
				Logger.temp("checking written word 0x%lx", *WrittenWordsIterator[tid]);
				if (a == *WrittenWordsIterator[tid]) {
					Logger.temp("Found in written words list, for writeback addr= 0x%lx, size = %d", addr, size);
					int temp_size = WrittenWordsInThisEpoch[tid].size();

					// [FIXME] this is valid with list, not valid with set.
					// WrittenWordsIterator[tid] = WrittenWordsInThisEpoch[tid].erase(WrittenWordsIterator[tid]);

					// For removal in list while iterating, special care is required.
					// updating is required like above, and special care for the beginning element is required.
					// The below routine is not perfect, because if -- result is the beginning, ++ in for loop
					// will pass the beginning element at next iteration.
					// For now, this is not required because only one element is found in the list.
					//if (WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].begin())
					//	WrittenWordsIterator[tid]--;
					Logger.temp("vector size decreases from %d to %d", temp_size, WrittenWordsInThisEpoch[tid].size());
					break;
				}
			}
			*/
			// set implementation
			WrittenWordsInThisEpoch[tid].erase(a);
			Logger.temp("writeback ends for %x.", a);
			Logger.log("[tid: %d] writeback ends for word 0x%x.", tid, a);
			break;
			//LC[tid].cleanEntry(a);  break;

		case writebackInvalidation:
			//LC[tid].cleanEntry(a);  LC[tid].removeEntry(a);  break;
			// like writeback
			Logger.temp("writeback and invalidation starts.");
			WrittenWordsInThisEpoch[tid].erase(a);
			Logger.temp("writeback and invalidation ends.");
			break;


		case loadBypass:
			Logger.temp("loadBypass starts.");
			ReadsMemBefore((ADDRINT) 0, tid, addr, size);
			Logger.temp("loadBypass ends.");
			break;

		case storeBypass:
			Logger.temp("storeBypass starts.");
			WritesMemBefore(0, tid, addr, size);
			Logger.temp("storeBypass ends.");
			break;

		case writebackMerge:
			// writebackMerge is completely the same as writeback.
			// Because this is traffic-optimization, does not change semantics.
			Logger.temp("writeback_merge starts.");
			// set implementation
			WrittenWordsInThisEpoch[tid].erase(a);
			Logger.temp("writeback_merge ends.");
			break;

		case writebackReserve:
			Logger.temp("writeback_reserve starts.");
			Logger.temp("writeback_reserve ends.");

			break;

		case writeFirst:
			// make the region as invalid to check write first.
			Logger.temp("writefirst starts.");

			Logger.temp("writefirst ends.");
			break;

		default:
			// not yet implemented
			break;
		}
	}

	// Range check for writebacks
	// This is for checking redundant writeback, leading to performance bugs.
	// if new writeback address overlaps previous writeback range in this epoch,
	// this is overlap, which should be informed to the programmer.
	// if not overlap, new address range is added to writeback map.
	if ((function == writeback) || (function == writebackInvalidation)) {
		map<ADDRINT, int>::iterator it;
		bool	overlap = false;

		for (it = WrittenBackInThisEpoch[tid].begin(); it != WrittenBackInThisEpoch[tid].end(); it++)
		{
			if ((*it).first > addr + size)	// already passed
				break;
			if ((addr + size > (*it).first) && (addr < (*it).first + (*it).second)) {
				overlap = true;
				// [FIXME] temporarilly, from warn to debug
				Logger.debug("tid(%d) tries to writeback address (0x%lx, 0x%x) which overlaps previous range (0x%lx, 0x%x)",
					tid, addr, size, (*it).first, (*it).second);
			}
		}

		// [TODO] Currently, if there is any overlap, this address is not added.
		// However, if part of the region overlaps, then remaining address should be added to writeback range.
		if (!overlap)
			WrittenBackInThisEpoch[tid].insert( pair<ADDRINT, int>(addr, size) );

		// [TODO] Check if this is for the latest data
		// [TODO] consider size. may need to be included in for loop.
		// word alignment should be considered.
		if (isGlobalVariable(addr)) {
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += 4)
			{
				Logger.temp("[tid: %d] addr2 = %lx", tid, addr2);
				if (bitVectorForGlobalVariable(addr2) == 0)
					//break;
					continue;
				for (int i = 0; i < MAX_THREADS; i++)
				{
					Logger.temp("i = %d", i);
					Logger.temp("bitvector = %lx", bitVectorForGlobalVariable(addr2));
					if ( (* (bitVectorForGlobalVariable(addr2)) )[i*2] == 0 &&
						 (* (bitVectorForGlobalVariable(addr2)) )[i*2+1] == 1 ) {
						Logger.temp("case 1");
						// 00 means unloaded state
						// 01 means read valid state **
						// 10 means write valid state
						// 11 means stale state
						(* (bitVectorForGlobalVariable(addr2)) )[i*2  ] = 1;
						(* (bitVectorForGlobalVariable(addr2)) )[i*2+1] = 1;
					}
					else if ( (* (bitVectorForGlobalVariable(addr2)) )[i*2] == 1 &&
							 (* (bitVectorForGlobalVariable(addr2)) )[i*2+1] == 0 ) {
						Logger.temp("case 2");
						// 00 means unloaded state
						// 01 means read valid state
						// 10 means write valid state **
						// 11 means stale state
						(* (bitVectorForGlobalVariable(addr2)) )[i*2  ] = 1;
						(* (bitVectorForGlobalVariable(addr2)) )[i*2+1] = 1;
						// [TODO] check this is required, or this has potential issues.
						// if other processor has write valid state, this may have potential violation.
					}
					// Added the case of unloaded state, assuming possible load of multi-line cache
					else if ( (* (bitVectorForGlobalVariable(addr2)) )[i*2] == 0 &&
							 (* (bitVectorForGlobalVariable(addr2)) )[i*2+1] == 0 ) {
						Logger.temp("case 2");
						// 00 means unloaded state
						// 01 means read valid state
						// 10 means write valid state **
						// 11 means stale state
						(* (bitVectorForGlobalVariable(addr2)) )[i*2  ] = 1;
						(* (bitVectorForGlobalVariable(addr2)) )[i*2+1] = 1;
						// [TODO] check this is required, or this has potential issues.
						// if other processor has write valid state, this may have potential violation.
					}
				}
				Logger.temp("case 3");
				// Guess the following is already done in WritesMemBefore.
				(* (bitVectorForGlobalVariable(addr2)) )[tid * 2] = 1;
				(* (bitVectorForGlobalVariable(addr2)) )[tid * 2+1] = 0;
				Logger.temp("[tid: %d] writeback to 0x%lx makes all other threads' state as stale.", tid, addr2);
			}
		}
		else if (MATracker.contain(addr)) {
			// [TODO] fill this!!!
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += 4)
			{
				for (int i = 0; i < MAX_THREADS; i++)
				{
					if ( (* (MATracker.bitVector(addr2)) )[i*2+1] == 1 ) {
						// 00 means unloaded state
						// 01 means valid state
						// 10 means stale state
						(* (MATracker.bitVector(addr2)) )[i*2  ] = 1;
						(* (MATracker.bitVector(addr2)) )[i*2+1] = 0;
					}
				}
				(* (MATracker.bitVector(addr2)) )[tid * 2] = 0;
				(* (MATracker.bitVector(addr2)) )[tid * 2+1] = 1;
				Logger.temp("[tid: %d] writeback to 0x%lx makes all other threads' state as stale.", tid, addr2);
			}
		}
	}

	if ((function == invalidation) || (function == writebackInvalidation)) {
		// [TODO] Check if this is for the latest data
		// [TODO] consider size. may need to be included in for loop.
		if (isGlobalVariable(addr)) {
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += 4)
			{
				(* (bitVectorForGlobalVariable(addr2)) )[tid * 2] = 0;
				(* (bitVectorForGlobalVariable(addr2)) )[tid * 2+1] = 0;
				Logger.temp("[tid: %d] invalidation to 0x%lx makes this threads' state as invalid.", tid, addr2);
			}
		}
		else if (MATracker.contain(addr)) {
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += 4)
			{
				(* (MATracker.bitVector(addr2)) )[tid * 2] = 0;
				(* (MATracker.bitVector(addr2)) )[tid * 2+1] = 0;
				Logger.temp("[tid: %d] invalidation to 0x%lx makes this threads' state as invalid.", tid, addr2);
			}
		}
	}
}


// Invalidation
VOID inv_word(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] inv_word -> addr 0x%p", tid, addr);
	PMC_process(invalidation, tid, (ADDRINT) addr, 4);
	ReleaseLock(&Lock);
	return;
}

VOID inv_dword(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] inv_dword -> addr 0x%p", tid, addr);
	PMC_process(invalidation, tid, (ADDRINT) addr, 8);
	ReleaseLock(&Lock);
	return;
}

VOID inv_qword(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] inv_qword -> addr 0x%p", tid, addr);
	PMC_process(invalidation, tid, (ADDRINT) addr, 16);
	ReleaseLock(&Lock);
	return;
}

VOID inv_range(THREADID tid, VOID *addr, int size)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] inv_range -> addr 0x%p, size %d 0x%x", tid, addr, size, size);
	PMC_process(invalidation, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}

// Writeback
VOID wb_word(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_word -> addr 0x%p", tid, addr);
	PMC_process(writeback, tid, (ADDRINT) addr, 4);
	ReleaseLock(&Lock);
	return;
}

VOID wb_long(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_long -> addr 0x%p", tid, addr);
	PMC_process(writeback, tid, (ADDRINT) addr, 8);
	ReleaseLock(&Lock);
	return;
}

VOID wb_longlong(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_longlong -> addr 0x%p", tid, addr);
	PMC_process(writeback, tid, (ADDRINT) addr, 16);
	ReleaseLock(&Lock);
	return;
}

VOID wb_range(THREADID tid, VOID *addr, int size)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_range -> addr 0x%p, size %d 0x%x", tid, addr, size, size);
	PMC_process(writeback, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}

// Writeback-and-invalidation
VOID wb_inv_word(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_inv_word -> addr 0x%p", tid, addr);
	PMC_process(writebackInvalidation, tid, (ADDRINT) addr, 4);
	ReleaseLock(&Lock);
	return;
}

VOID wb_inv_dword(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_inv_dword -> addr 0x%p", tid, addr);
	PMC_process(writebackInvalidation, tid, (ADDRINT) addr, 8);
	ReleaseLock(&Lock);
	return;
}

VOID wb_inv_qword(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_inv_qword -> addr 0x%p", tid, addr);
	PMC_process(writebackInvalidation, tid, (ADDRINT) addr, 16);
	ReleaseLock(&Lock);
	return;
}

VOID wb_inv_range(THREADID tid, VOID *addr, int size)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_inv_range -> addr 0x%p, size %d 0x%x", tid, addr, size, size);
	PMC_process(writebackInvalidation, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}

// Load/Store Bypass
VOID* ld_bypass(THREADID tid, VOID *addr)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] ld_bypass -> addr 0x%p", tid, addr);
	PMC_process(loadBypass, tid, (ADDRINT) addr, 4);

	// original meaning of the instruction
	// [CAUTION] Operation on 32-bit machine is not verified.
	ret = addr;
	ReleaseLock(&Lock);
	return ret;
}

VOID st_bypass(THREADID tid, VOID *addr, int value)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] st_bypass -> addr 0x%p", tid, addr);
	PMC_process(storeBypass, tid, (ADDRINT) addr, 4);

	// original meaning of the instruction
	// [CAUTION] Operation on 32-bit machine is not verified.
	* ( (int *) addr) = value;
	ReleaseLock(&Lock);
	return;
}

// Load Mem
// ldmem is deprecated
/*
VOID* ldmem(THREADID tid, VOID *addr)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.debug("");
	Logger.debug("From tid: %d, replaced function ldmem -> addr %p", tid, addr);
	PMC_process(loadMem, tid, (ADDRINT) addr, LINE_SIZE);

	// original meaning of the instruction
	// if word is dirty, keep it.
	// if not, update with memory content

	// [TODO] not implemented yet
	// Working on checking latest word is not done.
	// Working on adjacent word is not done.
	ret = addr;
	ReleaseLock(&Lock);
	return ret;
}
*/

// Writeback merge
VOID wb_merge(THREADID tid, VOID *addr, int size)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_merge -> addr 0x%p size %d 0x%x", tid, addr, size, size);
	PMC_process(writebackMerge, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}

// Writeback Reserve
VOID wb_reserve(THREADID tid, VOID *addr, int size)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_reserve -> addr 0x%p size %d 0x%x", tid, addr, size, size);
	PMC_process(writebackReserve, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}

// Writefirst
VOID wr_first(THREADID tid, VOID *addr, int size)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] writefirst -> addr 0x%p, size %d 0x%x", tid, addr, size, size);
	PMC_process(writeFirst, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}




VOID* barrierInitWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* bar, VOID* some, int num)
{
	VOID *ret;

	BarrierNumber = num;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret,
		PIN_PARG(VOID *), bar,
		PIN_PARG(VOID *), some,
		PIN_PARG(int), num,
		PIN_PARG_END());

	return ret;
}


VOID* barrierWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* bar)
{
	VOID *ret;


	Logger.log("[tid: %d] Executing barrier wrapper", tid);
	CheckBarrierResultBefore(tid);
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), bar, 
		PIN_PARG_END());

	return ret;
}


VOID* threadCreateWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4)
{
	VOID *ret;


	Logger.log("[tid: %d] Creating thread wrapper", tid);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret,
		PIN_PARG(VOID *), arg1,
		PIN_PARG(VOID *), arg2,
		PIN_PARG(VOID *), arg3,
		PIN_PARG(VOID *), arg4,
		PIN_PARG_END());

	return ret;
}


VOID* threadJoinWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* arg1, VOID* arg2)
{
	VOID *ret;


	Logger.log("[tid: %d] Joining thread wrapper", tid);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret,
		PIN_PARG(VOID *), arg1,
		PIN_PARG(VOID *), arg2,
		PIN_PARG_END());

	return ret;
}


VOID* gompBarrierWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* bar)
{
	VOID *ret;


	//Logger.log("[tid: %d] Executing GOMP barrier wrapper", tid);
	// temp, windy
	CheckBarrierResultBefore(tid);
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), bar, 
		PIN_PARG_END());

	return ret;
}


VOID* omp_set_num_threads_Wrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, int num)
{
	VOID *ret;

	Logger.log("[tid: %d] OpenMP number of threads is set to %d.\n", tid, num);
	BarrierNumber = num;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret,		// void
		PIN_PARG(int), num,
		PIN_PARG_END());

	return ret;
}


VOID* gomp_fini_work_share_Wrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* bar)
{
	VOID *ret;


	Logger.log("[tid: %d] Executing gomp_fini_work_share wrapper", tid);
	CheckBarrierResultBeforeGOMPImplicit(tid);
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 	// void
		PIN_PARG(VOID *), bar, 		// struct gomp_work_share *
		PIN_PARG_END());

	return ret;
}


VOID* GOMP_parallel_end_Wrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid)
{
	VOID *ret;


	Logger.log("[tid: %d] Executing GOM_parallel_end wrapper", tid);
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 	// void
		PIN_PARG_END());
	CheckBarrierResultBeforeGOMPImplicit(tid);


	return ret;
}



VOID* lockWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* mutex)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	MutexLocked = true;
	Logger.log("[tid: %d] Lock", tid);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG_END());

	ReleaseLock(&Lock);
	return ret;
}


VOID* unlockWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* mutex)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	// Another checking routine is required.
	//CheckBarrierResultBefore(tid);
	MutexLocked = false;
	Logger.log("[tid: %d] Unlock", tid);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG_END());

	ReleaseLock(&Lock);
	return ret;
}



//-------------------------------------------------------------------
//	Image Instrumentation
//-------------------------------------------------------------------

VOID ImageLoad(IMG img, VOID *v)
{
	RTN rtn;

	// tracking main function
	// when main function is started, MainRunning is set true.
	rtn = RTN_FindByName(img, "main");
	if (RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SpecialBefore,
			IARG_THREAD_ID,
			IARG_ADDRINT, "main",
			IARG_ADDRINT, RTN_Name(rtn).c_str(),
			IARG_ADDRINT, SEC_Name(RTN_Sec(rtn)).c_str(),
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)SpecialAfter, 
			IARG_THREAD_ID,
			IARG_ADDRINT, "main",
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
		RTN_Close(rtn);
	}

/*
	// This function call tracker works at entry point, but may not work at exit point.
	// Since Pin does not guarantee function exit point tracing,
	// if this is used, some valloc return value is missing.
	//
	// Current solution is to make function wrapper for valloc.

	// The same can be applied to malloc, calloc, realloc, and free.
	// malloc has the same interface.
	// calloc gets two arguments, so IARG_FUNCARG_ENTRYPOINT_VALUE, 1 is required.
	// FuncArg2IntIntBefore is used at IPOINT_BEFORE.
	// realloc gets two arguments with address and size. FuncArg2AddrIntBefore is required.
	// free gets address as an argument. FuncArg1AddrBefore is used.

	rtn = RTN_FindByName(img, "valloc");
	if (RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FuncArg1IntBefore, 
			IARG_THREAD_ID,
			IARG_ADDRINT, "valloc", 
			// The following two work as an alternative to entry point value.
			//IARG_G_ARG0_CALLEE,
			//IARG_FUNCARG_CALLSITE_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_ADDRINT, RTN_Name(rtn).c_str(),
			IARG_ADDRINT, SEC_Name(RTN_Sec(rtn)).c_str(),
			// At this moment, we do not care about image name.
			// IARG_ADDRINT, IMG_Name(SEC_Img(RTN_Sec(mallocRtn))).c_str(),
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FuncRetAddrAfter, 
			IARG_THREAD_ID,
			IARG_ADDRINT, "valloc",
			// The following works instead of exit point.
			// But, IARG_G_RESULT0 is deprecated.
			// IARG_G_RESULT0,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
		RTN_Close(rtn);
	}
*/

/*
	// To find caller function at callee site, this is written for test.
	rtn = RTN_FindByName(img, "malloc");
	if (RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FuncArg1IntBefore, 
			IARG_THREAD_ID,
			IARG_ADDRINT, "malloc", 
			// The following two work as an alternative to entry point value.
			//IARG_G_ARG0_CALLEE,
			//IARG_FUNCARG_CALLSITE_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_ADDRINT, RTN_Name(rtn).c_str(),
			IARG_ADDRINT, SEC_Name(RTN_Sec(rtn)).c_str(),
			// At this moment, we do not care about image name.
			//IARG_ADDRINT, IMG_Name(SEC_Img(RTN_Sec(mallocRtn))).c_str(),
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FuncRetAddrAfter, 
			IARG_THREAD_ID,
			IARG_ADDRINT, "malloc",
			// The following works instead of exit point.
			// But, IARG_G_RESULT0 is deprecated.
			// IARG_G_RESULT0,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
		RTN_Close(rtn);
	}
*/

	// wrappers for memory allocation/deallocation functions
	// valloc in pthread, malloc, calloc, realloc, free
	rtn = RTN_FindByName(img, "valloc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"valloc", PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(vallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	// malloc is used for many libraries which are executed by default.
	// To track our interested variables only, malloc_pmc is used in the application code.
	rtn = RTN_FindByName(img, "malloc_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"malloc_pmc", PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(mallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "calloc_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"calloc_pmc", PIN_PARG(int), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(callocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "realloc_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"realloc_pmc", PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(reallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "posix_memalign");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"posix_memalign", PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(reallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_END);
	}

	// more candidates: alloca, _alloca

	rtn = RTN_FindByName(img, "free_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"free_pmc", PIN_PARG(VOID *), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(freeWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
	}


	// PMC Instructions
	// Invalidation
	rtn = RTN_FindByName(img, "inv_word");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_word", PIN_PARG(unsigned long), PIN_PARG_END() );
		//RTN_Replace(rtn, AFUNPTR(inv_word));
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_word),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "inv_dword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_dword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_dword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

 	rtn = RTN_FindByName(img, "inv_qword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_qword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "inv_range");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_range", PIN_PARG(unsigned long), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_range),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_END);
	}

	// Writeback
	rtn = RTN_FindByName(img, "wb_word");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_word", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_word),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wb_dword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_dword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_long),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wb_qword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_longlong),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wb_range");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_range", PIN_PARG(unsigned long), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_range),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_END);
	}

	// Writeback & Invalidation
	rtn = RTN_FindByName(img, "wb_inv_word");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_word", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_word),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wb_inv_dword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_dword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_dword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wb_inv_qword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_qword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wb_inv_range");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_range", PIN_PARG(unsigned long), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_range),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_END);
	}

	// Bypass
	rtn = RTN_FindByName(img, "ld_bypass");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"ld_bypass", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(ld_bypass),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "st_bypass");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"st_bypass", PIN_PARG(unsigned long), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(st_bypass),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);
	}

	// LdMem
	/* LdMem is deprecated
	rtn = RTN_FindByName(img, "ldmem");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"ldmem", PIN_PARG(unsigned long), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(ldmem),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
	}
	*/

	rtn = RTN_FindByName(img, "wb_merge");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_merge", PIN_PARG(unsigned long), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_merge),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wr_first");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wr_first", PIN_PARG(unsigned long), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wr_first),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wb_reserve");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_reserve", PIN_PARG(unsigned long), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_reserve),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);
	}


	if (Category == PTHREAD) {
		// pthread_barrier_init
		rtn = RTN_FindByName(img, "pthread_barrier_init");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_barrier_init", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(barrierInitWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}

		// pthread_barrier_wait
		rtn = RTN_FindByName(img, "pthread_barrier_wait");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_barrier_wait", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(barrierWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		}

		/*
		// pthread_create
		rtn = RTN_FindByName(img, "pthread_create");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_create", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(threadCreateWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_END);
		}

		// pthread_join
		rtn = RTN_FindByName(img, "pthread_join");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_join", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(threadJoinWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_END);
		}
		*/

		/*
		// pthread_mutex_lock
		rtn = RTN_FindByName(img, "pthread_mutex_lock");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_mutex_lock", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(lockWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}

		// pthread_mutex_unlock
		rtn = RTN_FindByName(img, "pthread_mutex_unlock");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_mutex_unlock", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(unlockWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}
		*/
	}
	else if (Category == OPENMP) {

		// omp_set_num_threads
		rtn = RTN_FindByName(img, "omp_set_num_threads");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"omp_set_num_threads", PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(omp_set_num_threads_Wrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		}



		// GOMP_barrier for OpenMP
		rtn = RTN_FindByName(img, "GOMP_barrier");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"GOMP_barrier", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(gompBarrierWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		}

		// gomp_fini_work_share for OpenMP
		rtn = RTN_FindByName(img, "gomp_fini_work_share");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"gomp_fini_work_share", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(gomp_fini_work_share_Wrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		}


		// temp, windy 
		// gomp_fini_work_share for OpenMP
		// gcc 4.2.4 does not disclose gomp_fini_work-share.
		rtn = RTN_FindByName(img, "GOMP_parallel_end");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"GOM_parallel_end", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(GOMP_parallel_end_Wrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_END);
		}

	}
	else if (Category == GTHREAD) {
		// nothing is implemented yet.
		// for g_thread_create_full, g_thread_exit, g_thread_join
		// no barrier is implemented in gthread.
	}


}	// void ImageLoad



//-------------------------------------------------------------------
//	Functions for Routine Instrumentation
//-------------------------------------------------------------------

void AnalyzeBarrierRegion(int tid) 
{
	// Report if allocated memory is written but not written back.

	// source code reference for memory allocation is removed.
	//struct sourceLocation* sl;
	string s2;
	vector<struct GlobalVariableStruct>::iterator	it;
	//list<ADDRINT>::iterator	wit;
	set<ADDRINT>::iterator	wit;

	Logger.log("[tid: %d] *** Analyzing unwritten-back writes", tid);
	for (wit = WrittenWordsInThisEpoch[tid].begin(); wit != WrittenWordsInThisEpoch[tid].end(); wit++)
	{
		// check global variable
		BOOL done = false;
		for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
		{
			if ( (*wit >= (*it).addr) &&
				 (*wit < (*it).addr + (*it).size) ) {
				Logger.warn("0x%lx for %s (offset 0x%x %d) is not written back.", *wit, (*it).name.c_str(), (int) (*wit - (*it).addr), (int) (*wit - (*it).addr));
				done = true;
				break;
			}
		}
		if (done)
			continue;

		// check allocated memory
		s2 = MATracker.getVariableName(*wit);
		ADDRINT	allocAddr = 0;
		int		allocSize = 0;

		for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++) 
		{
			if (s2 == (*it).name) {
				allocAddr = (*it).allocAddr;
				allocSize = (*it).allocSize;
				Logger.warn("0x%lx, allocated in %s (0x%lx, offset x0%x %d), is not written back.", *wit,  s2.c_str(), allocAddr, (int) (*wit - allocAddr), (int) (*wit - allocAddr));
				break;
			}
		}

			
		/*
		sl = MATracker.getSource(*WrittenWordsIterator[i]);
		if (sl != NULL) {
			printf("variable is allocated in col: %d line: %d, filename: %s\n", sl->col, sl->line, sl->filename.c_str());
		}
		else
			Logger.warn("variable source is null\n");
			//printf("sl is null\n");
		*/
	}
	Logger.log("[tid: %d] *** Analysis for writeback is done.", tid);
}


void AnalyzeWritebacksAcrossThreads()
{
	Logger.log("*** Analyzing writebacks in the epoch across threads");

	map<ADDRINT, int>::iterator wbit, wbit2;

	for (int i = 0; i < NumThreads; i++)
	{
		for (wbit = WrittenBackInThisEpoch[i].begin(); wbit != WrittenBackInThisEpoch[i].end(); wbit++)
		{
			for (int j = i+1; j < NumThreads; j++)
			{
				for (wbit2 = WrittenBackInThisEpoch[j].begin(); wbit2 != WrittenBackInThisEpoch[j].end(); wbit2++)
				{
					if ( ((*wbit).first + (*wbit).second) < (*wbit2).first )
						// writeback address of comprison is bigger than original address
						break;
					
					if ( (*wbit).first < ((*wbit2).first + (*wbit2).second) ) {
						if ( ((*wbit).first + (*wbit).second) > (*wbit2).first ) {
							Logger.error("tid: %d and tid: %d makes conflict in writeback", i, j);
							Logger.error("addr range (0x%lx, %x), (0x%lx, %x)", (*wbit).first, (*wbit).second, (*wbit2).first, (*wbit2).second);
						}
					}
				}	// writeback traversal for tid j
			}	// for j
		}	// writeback traversal for tid i
	}	// for i

	for (int i = 0; i < NumThreads; i++)
		WrittenBackInThisEpoch[i].clear();

	Logger.log("*** Analysis for writebacks across threads is done.");
}


void CheckBarrierResult(THREADID tid, int ret)
{
	// The reference manual of Pin tool says return value has ADDRINT type,
	// but it does not make sense. With unsigned type, ret is recognized as FFFF for -1.
	// Thus, ret is declared as int.

	GetLock(&Lock, tid+1);
	//printf("[LOG] [tid: %d] returned pthread_barrier_wait with %d\n", tid, ret);

	// phase proceeding in each thread
	//LC[tid].phase++;

	if (ret == 0) {
		// meaning tid-th thread arrives at the barrier

		// writeback is checked for this epoch.
		Logger.log("tid: %d has reached to barrier %d", tid, BarrierCount);
		AnalyzeBarrierRegion(tid);
		WrittenWordsInThisEpoch[tid].clear();
	}
	else if (ret == -1) {
		// meaning if (ret == PTHREAD_BARRIER_SERIAL_THREAD)
		// If return value is -1, the last coming thread
		//StatsCounter::allNextPhase();		
		Logger.log("tid: %d has reached to barrier %d", tid, BarrierCount);
		AnalyzeBarrierRegion(tid);
		Logger.log("Barrier region %d ended.", BarrierCount);
		AnalyzeWritebacksAcrossThreads();
		BarrierCount++;
		Logger.log("***********************");
	}

	ReleaseLock(&Lock);
}


void CheckBarrierResultBefore(THREADID tid)
{
	// temp, windy
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] reached to barrier %d", tid, BarrierCount);

	// phase proceeding in each thread
	//LC[tid].phase++;

	AnalyzeBarrierRegion(tid);
	WrittenWordsInThisEpoch[tid].clear();

	//if (++CurrentBarrierArrival == NumThreads - 1) {
	if (++CurrentBarrierArrival == BarrierNumber) {
		// Because we do not count main thread, NumThreads - 1 is used.

		// Analyze overlapping writebacks across threads.
		// In fact, overlapping should be checked for writes, however, 
		// as long as writes are written back, this is okay.
		// temp, windy
		//AnalyzeWritebacksAcrossThreads();
		Logger.warn("*** Barrier %d ended ***\n\n", BarrierCount);
		BarrierCount++;
		CurrentBarrierArrival = 0;
	}

	// temp, windy
	ReleaseLock(&Lock);
}

void CheckBarrierResultBeforeGOMPImplicit(THREADID tid)
{
	// temp, windy
	GetLock(&Lock, tid+1);

	Logger.log("Reached to GOMP implicit barrier %d", BarrierCount);

	// phase proceeding in each thread
	//LC[tid].phase++;

	for (int i = 0; i < BarrierNumber; i++) 
		AnalyzeBarrierRegion(i);
	for (int i = 0; i < BarrierNumber; i++) 
		WrittenWordsInThisEpoch[i].clear();

	// For OpenMP, this function is called only by master thread.
	// [TODO] This is not sure if it is okay to call writeback across threads test now.
	// temp, windy
	//AnalyzeWritebacksAcrossThreads();
	Logger.warn("*** Barrier %d ended *** (gomp parallel)\n\n", BarrierCount);
	BarrierCount++;

	// temp, windy
	ReleaseLock(&Lock);
}



/*
//	This is replaced with ImageLoad.
void VallocBefore(THREADID tid)
{
	GetLock(&Lock, tid+1);
	fprintf(Trace, "[tid: %d] valloc starts\n", tid);
	fflush(Trace);
	ReleaseLock(&Lock);
}


void VallocAfter(THREADID tid, int ret)
{
	GetLock(&Lock, tid+1);
	fprintf(Trace, "[tid: %d]   valloc returns with %d\n", tid, ret);
	fflush(Trace);
	ReleaseLock(&Lock);
}
*/


void lockWrapperBefore(THREADID tid)
{
	MutexLocked = true;
	Logger.log("[tid: %d] Lock", tid);
}


void unlockWrapperBefore(THREADID tid)
{
	MutexLocked = false;
	Logger.log("[tid: %d] Unlock", tid);
}


//-------------------------------------------------------------------
//	Routine Instrumentation
//-------------------------------------------------------------------
VOID Routine(RTN rtn, VOID *v)
{
	string s = RTN_Name(rtn);

	RTN_Open(rtn);

	// pthread_barrier_wait is contained in libpthread.so.0 when dynamically linked.
	// main segment can have this function when statically linked.
	// Current SPLASH-2 kernels with static linking have pthread_barrier_wait as a separate function.
	// IPOINT_AFTER may not recognize the end of the function, but for pthread_barrier_wait,
	// it seems to be working.

	/*
	if (s == "pthread_barrier_wait")
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) CheckBarrierResult,
			IARG_THREAD_ID,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
	*/

	/*
	//	Instead of check barrier result after the function call, before the function call is preferred here.
	//	When pthread_barrier_wait returns -1, it does not mean all other threads are waiting for this thread.
	//	Other threads can proceed, so analysis cannot make the correct result in this case.
	if (s == "pthread_barrier_wait")
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) CheckBarrierResultBefore,
			IARG_THREAD_ID,
			IARG_END);
	*/

	// pmcthread_barrier_wait is made for very correct result.
	if (s == "pmcthread_barrier_wait")
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) CheckBarrierResultBefore,
			IARG_THREAD_ID,
			IARG_END);


/*
	// This routine has a problem in exit point.
	// Pin does not guarantee every exit point is captured with this routine.
	// In addition, valloc can appear as extended name such as __libc_valloc.
	// 
	// Current solution is to make function wrapper for valloc.
	if (s == "valloc" || s == "__libc_valloc") {
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) VallocBefore,
			IARG_THREAD_ID,
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) VallocAfter,
			IARG_THREAD_ID, 
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
	}
*/

	if (s == "pthread_mutex_lock")
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) lockWrapperBefore,
			IARG_THREAD_ID,
			IARG_END);

	if (s == "pthread_mutex_unlock")
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) unlockWrapperBefore,
			IARG_THREAD_ID,
			IARG_END);

	RTN_Close(rtn);
}



//-------------------------------------------------------------------
//	Functions for Instruction Instrumentation
//-------------------------------------------------------------------

VOID ReadsMemBefore (ADDRINT applicationIp, THREADID tid, ADDRINT memoryAddressRead, UINT32 memoryReadSize)
{
	ADDRINT startWordAddress, endWordAddress, startOffset;
	ADDRINT offsetMask = 0x3;

	// Before main running, we do not track read/write access.
	if (!MainRunning)
		return;

	GetLock(&Lock, tid+1);
	// if read is from allocated memory
	if (MATracker.contain(memoryAddressRead)) {
		// File trace is disabled for now.
		//GetLock(&Lock, tid+1);
		//fprintf(Trace, "[tid: %d] %d Read address = 0x%lx\n", tid, BarrierCount, memoryAddressRead);
		//fflush(Trace);
		NumReads[tid].count++;
		//ReleaseLock(&Lock);

		if (MutexLocked)
			Logger.temp("[tid: %d] epoch: %d Locked / Read address = 0x%lx", tid, BarrierCount, memoryAddressRead);
		else
			Logger.temp("[tid: %d] epoch: %d Read address = 0x%lx", tid, BarrierCount, memoryAddressRead);


		startWordAddress = memoryAddressRead & ADDR_MASK;
		endWordAddress = (memoryAddressRead + memoryReadSize) & ADDR_MASK;
		startOffset = memoryAddressRead & offsetMask;

		for (ADDRINT a = startWordAddress; a < memoryAddressRead + memoryReadSize; a += 4)
		{
			// invalidation test
			if ( (* (MATracker.bitVector(a)) )[tid*2] == 1) {
				if ( (* (MATracker.bitVector(a)) )[tid*2+1] == 1) {
					// means 'need invalidation'
					Logger.error("[tid: %d] read without invalidation: addr=0x%lx, %s (offset %ld 0x%lx)", tid, a, MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
				}
				// '10' means write valid. So, no action.
			}
			else if ( (* (MATracker.bitVector(a)) )[tid*2+1] == 0) {
				// means currently invalid state
				Logger.temp("read at unloaded state");
				(* (MATracker.bitVector(a)) )[tid*2+1] = 1;	// changed to read valid state
			}
		}
	}
	// else if read is from global memory
	else if (isGlobalVariable(memoryAddressRead)) {
		// File trace is disabled for now.
		//fprintf(Trace, "[tid: %d] %d Read address = 0x%lx\n", tid, BarrierCount, memoryAddressRead);
		//fflush(Trace);
		NumReads[tid].count++;
		//ReleaseLock(&Lock);

		if (MutexLocked)
			Logger.temp("[tid: %d] epoch: %d Locked / Read address = 0x%lx", tid, BarrierCount, memoryAddressRead);
		else
			Logger.temp("[tid: %d] epoch: %d Read address = 0x%lx", tid, BarrierCount, memoryAddressRead);


		startWordAddress = memoryAddressRead & ADDR_MASK;
		endWordAddress = (memoryAddressRead + memoryReadSize) & ADDR_MASK;
		startOffset = memoryAddressRead & offsetMask;

		for (ADDRINT a = startWordAddress; a < memoryAddressRead + memoryReadSize; a += 4)
		{
				//	Logger.warn("[tid: %d] read : %s, %lx", tid, getGlobalVariableName(a), a);
			// invalidation test
			if ( (* (bitVectorForGlobalVariable(a)) )[tid*2] == 1) {
				if ( (* (bitVectorForGlobalVariable(a)) )[tid*2+1] == 1) {
					// means 'need invalidation'
					Logger.error("[tid: %d] read without invalidation: addr=0x%lx, %s (offset: %ld 0x%lx)", tid, a, getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
				}
			}
			else if ( (* (bitVectorForGlobalVariable(a)) )[tid*2+1] == 0) {
				// means currently invalid state
				Logger.temp("read at unloaded state");
				(* (bitVectorForGlobalVariable(a)) )[tid*2+1] = 1;	// change to read valid state
			}
		}
	}
	ReleaseLock(&Lock);
}


VOID WritesMemBefore(ADDRINT applicationIp, THREADID tid, ADDRINT memoryAddressWrite, UINT32 memoryWriteSize)
{
	ADDRINT startWordAddress, endWordAddress, startOffset;
	ADDRINT offsetMask = 0x3;

	// Before main running, we do not track read/write access.
	if (!MainRunning)
		return;

	GetLock(&Lock, tid+1);
	// For memory-allocated address, written words should be recorded.
	if (MATracker.contain(memoryAddressWrite)) {
		// File trace is disabled for now.
		//GetLock(&Lock, tid+1);
		//fprintf(Trace, "[tid: %d] %d Write address = 0x%lx\n", tid, BarrierCount, memoryAddressWrite);
		//fflush(Trace);
		NumWrites[tid].count++;
		//ReleaseLock(&Lock);


		Logger.temp("[tid: %d] epoch: %d Write address = 0x%lx",
			tid, BarrierCount, memoryAddressWrite);

		if (MutexLocked)
			Logger.temp("[tid: %d] epoch: %d Locked / Write address = 0x%lx to %s",
				tid, BarrierCount, memoryAddressWrite, MATracker.getVariableName(memoryAddressWrite).c_str());
		else
			Logger.temp("[tid: %d] epoch: %d Write address = 0x%lx to %s",
				tid, BarrierCount, memoryAddressWrite, MATracker.getVariableName(memoryAddressWrite).c_str());

		startWordAddress = memoryAddressWrite & ADDR_MASK;
		endWordAddress = (memoryAddressWrite + memoryWriteSize) & ADDR_MASK;
		startOffset = memoryAddressWrite & offsetMask;

		for (ADDRINT a = startWordAddress; a < memoryAddressWrite + memoryWriteSize; a += 4)
		{
			if (MutexLocked) {
				// add this word to written words group
				/*
				for (WrittenWordsIterator[tid] = WrittenWordsInThisLock[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisLock[tid].end(); WrittenWordsIterator[tid]++)
				{
					if (*WrittenWordsIterator[tid] == a)
						break;
				}

				if (WrittenWordsIterator[tid] == WrittenWordsInThisLock[tid].end())
					WrittenWordsInThisLock[tid].push_back(a);
				*/

				// set implementation
				WrittenWordsInThisLock[tid].insert(a);
			}
			else {
				// add this word to written words group
				/*
				for (WrittenWordsIterator[tid] = WrittenWordsInThisEpoch[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end(); WrittenWordsIterator[tid]++)
				{
					if (*WrittenWordsIterator[tid] == a)
						break;
				}

				if (WrittenWordsIterator[tid] == WrittenWordsInThisEpoch[tid].end())
					// For list,
					//WrittenWordsInThisEpoch[tid].push_back(a);
					// For set,
					WrittenWordsInThisEpoch[tid].insert(WrittenWordsIterator[tid], a);
				*/

				// set implementation
				WrittenWordsInThisEpoch[tid].insert(a);
			}

			// Checking if this is the latest word
			// However, for writes, this may not be required.
			if ( (* (MATracker.bitVector(a)) )[tid*2] == 1) {
				if ( (* (MATracker.bitVector(a)) )[tid*2+1] == 1) {
					// means 'need invalidation'
					Logger.warn("[tid: %d] write without invalidation: %s (offset %ld 0x%lx)", tid, MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
				}
			}
			else if ( (* (MATracker.bitVector(a)) )[tid*2+1] == 0) {
				// means currently invalid state
				Logger.temp("write at unloaded state");
				(* (MATracker.bitVector(a)) )[tid*2] = 1;
				(* (MATracker.bitVector(a)) )[tid*2+1] = 0;
			}
			else if ( (* (MATracker.bitVector(a)) )[tid*2+1] == 1) {
				// means currently read valid state
				Logger.temp("write at read valid state");
				(* (MATracker.bitVector(a)) )[tid*2] = 1;
				(* (MATracker.bitVector(a)) )[tid*2+1] = 0;
			}
		}

	}
	// For general global memory variables, written words should be recorded.
	else if (isGlobalVariable(memoryAddressWrite)) {
		// File trace is disabled for now.
		//GetLock(&Lock, tid+1);
		//fprintf(Trace, "[tid: %d] %d Write address = 0x%lx\n", tid, BarrierCount, memoryAddressWrite);
		//fflush(Trace);
		NumWrites[tid].count++;
		//ReleaseLock(&Lock);


		if (MutexLocked)
			Logger.temp("[tid: %d] epoch: %d Locked / Write address = 0x%lx to %s",
				tid, BarrierCount, memoryAddressWrite, getGlobalVariableName(memoryAddressWrite));
		else
			Logger.temp("[tid: %d] epoch:%d Write address = 0x%lx to %s",
				tid, BarrierCount, memoryAddressWrite, getGlobalVariableName(memoryAddressWrite));

		startWordAddress = memoryAddressWrite & ADDR_MASK;
		endWordAddress = (memoryAddressWrite + memoryWriteSize) & ADDR_MASK;
		startOffset = memoryAddressWrite & offsetMask;

		for (ADDRINT a = startWordAddress; a < memoryAddressWrite + memoryWriteSize; a += 4)
		{
			if (MutexLocked) {
				/*
				for (WrittenWordsIterator[tid] = WrittenWordsInThisLock[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end(); WrittenWordsIterator[tid]++)
				{
					if (*WrittenWordsIterator[tid] == a)
						break;
				}

				if (WrittenWordsIterator[tid] == WrittenWordsInThisLock[tid].end())
					// if not added yet, add it
					WrittenWordsInThisLock[tid].push_back(a);
				*/

				// set implementation
				WrittenWordsInThisLock[tid].insert(a);
			}
			else {
				/*
				for (WrittenWordsIterator[tid] = WrittenWordsInThisEpoch[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end(); WrittenWordsIterator[tid]++)
				{
					if (*WrittenWordsIterator[tid] == a)
						break;
				}

				if (WrittenWordsIterator[tid] == WrittenWordsInThisEpoch[tid].end())
					// if not added yet, add it
					WrittenWordsInThisEpoch[tid].push_back(a);
				*/

				// set implementation
				WrittenWordsInThisEpoch[tid].insert(a);
			}

			if ( (* (bitVectorForGlobalVariable(a)) )[tid*2] == 1) {
				if ( (* (bitVectorForGlobalVariable(a)) )[tid*2+1] == 1) {
					// means 'need invalidation'
					Logger.warn("[tid: %d] write without invalidation: %s (offset: %ld 0x%lx)", tid, getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
				}
			}
			else if ( (* (bitVectorForGlobalVariable(a)) )[tid*2+1] == 0) {
				// means currently invalid state
				Logger.temp("write at unloaded state");
				(* (bitVectorForGlobalVariable(a)) )[tid*2] = 1;
				(* (bitVectorForGlobalVariable(a)) )[tid*2+1] = 0;
			}
			else if ( (* (bitVectorForGlobalVariable(a)) )[tid*2+1] == 1) {
				// means currently read valid state
				Logger.temp("write at read valid state");
				(* (bitVectorForGlobalVariable(a)) )[tid*2] = 1;
				(* (bitVectorForGlobalVariable(a)) )[tid*2+1] = 0;
			}
		}

	}

	if (AfterAlloc[tid]) {
		// Standard library malloc returns pointer to the variable in rax.
		// So, I guess the first write instruction with rax after malloc call has the pointer assignment.
		//
		// Currently checking if this instruction is for malloc statement is ugly.
		// [TODO] Find the better way without string comparison
		// printf("%s\n", DisAssemblyMap[applicationIp].c_str());
		if (strstr(DisAssemblyMap[applicationIp].c_str(), "rax")) {
			// Source code tracing
			INT32	col, line;
			string	filename;

			// temp, windy
			PIN_LockClient();
			PIN_GetSourceLocation(applicationIp, &col, &line, &filename);
			PIN_UnlockClient();

			Logger.log("[tid: %d] Memory allocation was done in location: col %d line %d file %s\n", tid, col, line, filename.c_str());

			MATracker.addSource(col, line, filename);

			// Global variable tracing
			//printf("[DEBUG] allocation 0x%lx\n", memoryAddressWrite);
			for (GlobalVariableVecIterator = GlobalVariableVec.begin(); GlobalVariableVecIterator != GlobalVariableVec.end(); GlobalVariableVecIterator++)
			{
				if ((*GlobalVariableVecIterator).addr == memoryAddressWrite) {
					MATracker.addVariableName((*GlobalVariableVecIterator).name, 0);
					(*GlobalVariableVecIterator).allocAddr = MATracker.prevAddr;
					(*GlobalVariableVecIterator).allocSize = MATracker.prevSize;
					(*GlobalVariableVecIterator).attachState();
				}
				else if ( ((*GlobalVariableVecIterator).addr < memoryAddressWrite) &&
					(memoryAddressWrite < (*GlobalVariableVecIterator).addr + (*GlobalVariableVecIterator).size) ) {
					int offset = ((*GlobalVariableVecIterator).addr + (*GlobalVariableVecIterator).size - memoryAddressWrite) / 8;
					MATracker.addVariableName((*GlobalVariableVecIterator).name, offset);
				}
			}

			AfterAlloc[tid] = false;
		}
	}
	ReleaseLock(&Lock);
}	// void WritesMemBefore



//-------------------------------------------------------------------
//	Instruction Instrumentation
//-------------------------------------------------------------------

VOID Instruction(INS ins, void * v)
{
	// Finally, we will target parall worker threads only, which has threadid > 0.
	// This requires SESC to equip processor 0 with ideal memory, and instrumenting function drops its job in case of threadid 0.
	// At this moment, instrumentation targets all threads including main thread.

	//UINT32 tid = PIN_ThreadId();
	//GetLock(&Lock, tid+1);
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	// Checker functions
	// if (memOperands > 1)
	//	printf("multi: %lx: %d: %s\n", INS_Address(ins), memOperands, INS_Disassemble(ins).c_str());
	// if (INS_IsAtomicUpdate(ins))
	//	printf("atomic %lx: %d: %s\n", INS_Address(ins), memOperands, INS_Disassemble(ins).c_str());


	// Iterate over each memory operand of the instruction
	for (UINT32 memOp = 0; memOp < memOperands; memOp++) 
	{
		DisAssemblyMap[INS_Address(ins)] = INS_Disassemble(ins);
		//AllMemInstructions.inc();
		//printf("INS_Address(ins) = 0x%lx\n", INS_Address(ins));

		// INS_InsertPredicatedCall is identical to INS_InsertCall except predicated instructions.
		// Predicated instructions are CMOVcc, FCMOVcc and REPped string ops.

		if (INS_MemoryOperandIsRead(ins, memOp)) {
			// read operation

			// jmp, call, ret do read, but these are for control flow.
			// More data cache related, not our concern.			
			if (!(INS_IsBranch(ins) || INS_IsCall(ins) || INS_IsRet(ins)))
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) ReadsMemBefore,
					IARG_INST_PTR,
					IARG_THREAD_ID,
					IARG_MEMORYOP_EA, memOp,
					IARG_MEMORYREAD_SIZE,
					IARG_END);
			
		}

		if (INS_MemoryOperandIsWritten(ins, memOp)) {
			// write operation

			// call instruction does write, but this is for control flow, not our concern.			
			if (!INS_IsCall(ins))
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) WritesMemBefore,
					IARG_INST_PTR,// application IP
					IARG_THREAD_ID, 
					IARG_MEMORYOP_EA, memOp,
					IARG_MEMORYWRITE_SIZE,
					IARG_END);
		}
	}	// end of for loop, memOp
	//ReleaseLock(&Lock);
}	// void Instruction



//-------------------------------------------------------------------
//	Thread Tracker
//-------------------------------------------------------------------

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *V)
{
	GetLock(&Lock, tid+1);

	Logger.log("[tid: %d] *** thread is started.\n", tid);

	// MaxThreads
	NumThreads++;
	if (MaxThreads < NumThreads)
		MaxThreads = NumThreads;
	
	if (NumThreads == 2) {
		// if first thread spawning, we need to check current writeback status.

		AnalyzeBarrierRegion(0);
		WrittenWordsInThisEpoch[0].clear();

		// temp, windy
		Logger.warn("*** Epoch %d ended ***", BarrierCount);

		BarrierCount++;
	}

	ReleaseLock(&Lock);
}


VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 flags, VOID *V)
{
	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] *** thread is finished.\n", tid);

	NumThreads--;

	AnalyzeBarrierRegion(0);
	WrittenWordsInThisEpoch[0].clear();

	if (NumThreads == 1) {
		// temp, windy
		Logger.warn("*** Epoch %d ended ***", BarrierCount);
		
		BarrierCount++;
	}
	
	ReleaseLock(&Lock);
}



//-------------------------------------------------------------------
//	Finalize
//-------------------------------------------------------------------

VOID FinalAnalysis()
{
	Logger.log("\n\n *** Final Analysis ***\n");
	// Basic read/write info per thread
	for (int i = 0; i < MaxThreads; i++) {
		Logger.log("tid=%d, reads=%ld, writes=%ld\n", i, NumReads[i].count, NumWrites[i].count);
	}


	// Report if allocated memory is written but not written back.

	// source code reference for memory allocation is removed.
	//struct sourceLocation* sl;
	string s2;
	vector<struct GlobalVariableStruct>::iterator	it;
	//list<ADDRINT>::iterator	wit;
	set<ADDRINT>::iterator		wit;

	for (int i = 0; i < MaxThreads; i++) {
		Logger.log("In thread %d,\n", i);
		for (wit = WrittenWordsInThisEpoch[i].begin(); wit != WrittenWordsInThisEpoch[i].end(); wit++)
		{
			// check global variable
			BOOL done = false;
			for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
			{
				if ( (*wit >= (*it).addr) &&
					 (*wit < (*it).addr + (*it).size) ) {
					Logger.log("0x%lx for %s (offset 0x%x %d) is not written back.\n", *wit, (*it).name.c_str(), (int) (*wit - (*it).addr), (int) (*wit - (*it).addr));
					done = true;
					break;
				}
			}
			if (done)
				continue;

			// check allocated memory
			s2 = MATracker.getVariableName(*wit);
			ADDRINT	allocAddr = 0;
			int		allocSize = 0;

			for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++) 
			{
				if (s2 == (*it).name) {
					allocAddr = (*it).allocAddr;
					allocSize = (*it).allocSize;
					break;
				}
			}

			Logger.log("0x%lx, allocated in %s (0x%lx, offset 0x%x %d), is not written back.\n", *wit,  s2.c_str(), allocAddr, (int) (*wit - allocAddr), (int) (*wit - allocAddr));
			
			/*
			sl = MATracker.getSource(*WrittenWordsIterator[i]);
			if (sl != NULL) {
				printf("variable is allocated in col: %d line: %d, filename: %s\n", sl->col, sl->line, sl->filename.c_str());
			}
			else
				Logger.warn("variable source is null\n");
				//printf("sl is null\n");
			*/

		}
	}
}	// void FinalAnalysis


VOID Fini(INT32 code, VOID *v)
{
	// Anything required for final analysis should be written here.
	// [FIXME] final analysis is commented out temporarilly.
	//FinalAnalysis();

	Logger.close();

	printf("\n\n# of threads were running: %d\n", MaxThreads);
	printf("# of barrier regions: %d\n", BarrierCount+1);
}



//-------------------------------------------------------------------
//	Print Usage
//-------------------------------------------------------------------

INT32 Usage()
{
	PIN_ERROR("Checker Tool for PMC Architecture\n\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}


//-------------------------------------------------------------------
//	Read Variable Info File
//-------------------------------------------------------------------

VOID ReadVariableInfo(char *filename)
{
	FILE		*fp;
	char		line[100];
	char		id[100];
	ADDRINT		addr;
	int			size;
	string		name;


	fp = fopen(filename, "r");
	if (fp == NULL) {
		Logger.error("file cannot be opened: %s", filename);
		return ;
	}
	while ( fgets(line, 100, fp) != NULL) {
		sscanf(line, "%s %lx %x", id, &addr, &size);
		if (ExcludePotentialSystemVariables) {
			if ((id[0] == '.') || (id[0] == '_'))
				continue;
			if (!strcmp("stdin", id) || !strcmp("stdout", id) || !strcmp("stderr", id))
				continue;
		}
		name = id;
		GlobalVariableVec.push_back(GlobalVariableStruct(name, addr, size, 0, 0));
	}		

	fclose(fp);
}



//-------------------------------------------------------------------
//	Read Configuration File
//-------------------------------------------------------------------

VOID ReadConfigurationFile(const char *filename)
{
	FILE		*fp;
	char		line[100];
	char		*str;


	fp = fopen(filename, "r");
	if (fp == NULL) {
		Logger.error("Config file cannot be opened: %s", filename);
		return ;
	}

	while ( fgets(line, 100, fp) != NULL) {
		str = strtok(line, "=\n\t ");
		if (str == NULL)
			continue;
		if (strlen(str) < 3)
			continue;

		if ((str[0] == '/') && (str[1] == '/'))	// comment
			continue;
		
		// Category
		if (!strcasecmp(str, "category")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "pthread")) {
				Category = PTHREAD;
			}
			else if (!strcasecmp(str, "openmp")) {
				Category = OPENMP;
			}
			else if (!strcasecmp(str, "gthread")) {
				Category = GTHREAD;
			}
		}

		// Display
		if (!strcasecmp(str, "display")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "none")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_NONE);
			}
			else if (!strcasecmp(str, "error")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_ERROR);
			}
			else if (!strcasecmp(str, "warning")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_WARNING);
			}
			else if (!strcasecmp(str, "log")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_LOG);
			}
			else if (!strcasecmp(str, "debug")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_DEBUG);
			}
			else if (!strcasecmp(str, "temp")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_TEMP_DEBUG);
			}
		}

		if (!strcasecmp(str, "file")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "none")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_NONE);
			}
			else if (!strcasecmp(str, "error")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_ERROR);
			}
			else if (!strcasecmp(str, "warning")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_WARNING);
			}
			else if (!strcasecmp(str, "log")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_LOG);
			}
			else if (!strcasecmp(str, "debug")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_DEBUG);
			}
			else if (!strcasecmp(str, "temp")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_TEMP_DEBUG);
			}
		}

		if (!strcasecmp(str, "suggestion")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "true")) {
				Suggestion = true;
			}
			else if (!strcasecmp(str, "false")) {
				Suggestion = false;
			}
		}

		if (!strcasecmp(str, "filename")) {
			str = strtok(NULL, "=\n\t ");
			strcpy(OutputFileName, str);
		}

		if (!strcasecmp(str, "max_worker_threads")) {
			str = strtok(NULL, "=\n\t ");
			MaxWorkerThreads = atoi(str);
		}

		if (!strcasecmp(str, "cache_line_size")) {
			str = strtok(NULL, "=\n\t ");
			CacheLineSize = atoi(str);
		}

		if (!strcasecmp(str, "global_variable_file")) {
			str = strtok(NULL, "=\n\t ");
			strcpy(VariableFileName, str);
		}

		if (!strcasecmp(str, "exclude_potential_system_variables")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "true")) {
				ExcludePotentialSystemVariables = true;
			}
			else if (!strcasecmp(str, "false")) {
				ExcludePotentialSystemVariables = false;
			}
		}	

		if (!strcasecmp(str, "tracking_after_main")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "true")) {
				AfterMainTracking = true;
			}
			else if (!strcasecmp(str, "false")) {
				AfterMainTracking = false;
			}
		}	

		if (!strcasecmp(str, "mem_alloc_function")) {
			str = strtok(NULL, "=\n\t ");
			printf("mem_alloc_function = %s\n", str);
		}

		if (!strcasecmp(str, "mem_dealloc_function")) {
			str = strtok(NULL, "=\n\t ");
			printf("mem_dealloc_function = %s\n", str);
		}

		if (!strcasecmp(str, "tracking_master_thread_only")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "true")) {
				MasterThreadOnlyAllocFree = true;
			}
			else if (!strcasecmp(str, "false")) {
				MasterThreadOnlyAllocFree = false;
			}
		}	
	}

	fclose(fp);
}


//	key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY tls_key;

//	function to access thread-specific data
thread_data_t* get_tls(THREADID threadid)
{
	thread_data_t* tdata =
		static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
	return tdata;
}



//-------------------------------------------------------------------
//	Main Function
//-------------------------------------------------------------------

int main(int argc, char * argv[]) 
{
	// Initialization
	// [TODO] Giving arguments through pin execution was not successful.
	// if possible, having an argument for configuration file name is desirable.
	PIN_InitSymbols();
	if (PIN_Init(argc, argv))
		return Usage();

	// initialization before configuration
	// These will be overwritten by configuration if there are corresponding configuration items in the file.
	Category = UNKNOWN;
	Suggestion = true;
	strcpy(OutputFileName, "coach.out");
	MaxWorkerThreads = 32;
	CacheLineSize = 64;
	strcpy(VariableFileName, "variable_info.txt");
	ExcludePotentialSystemVariables = true;
	AfterMainTracking = true;
	MainRunning = false;
	MasterThreadOnlyAllocFree = true;

	// Configuration file
	ReadConfigurationFile(configFileName);
	if (AfterMainTracking == true)
		MainRunning = false;
	else
		MainRunning = true;

	// file for log output
	OutputFile = fopen(OutputFileName, "w");
	Logger.setOutputFile(OutputFile);

	InitLock(&Lock);
	MaxThreads = 0;
	NumThreads = 0;
	CurrentBarrierArrival = 0;
	BarrierCount = 0;
	for (int i = 0; i < MAX_THREADS; i++) {
		NumReads[i].count = NumWrites[i].count = 0;
		AfterAlloc[i] = false;
	}

	ReadVariableInfo(VariableFileName);
	Logger.log("*** Global Variable List starts");
	for (GlobalVariableVecIterator = GlobalVariableVec.begin(); GlobalVariableVecIterator != GlobalVariableVec.end(); GlobalVariableVecIterator++) 
	{
		Logger.log("%s: addr=0x%lx, len=0x%x", (*GlobalVariableVecIterator).name.c_str(), (*GlobalVariableVecIterator).addr, (*GlobalVariableVecIterator).size);
	}
	Logger.log("*** Global Variable List ends\n");


	// Instrumentation
	// At image level,
	IMG_AddInstrumentFunction(ImageLoad, 0);

	// At routine level,
	RTN_AddInstrumentFunction(Routine, 0);

	// At instruction level,
	INS_AddInstrumentFunction(Instruction, 0);

	// Add special functions
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();		// this never returns
	return 0;
}

