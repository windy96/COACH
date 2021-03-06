/*
 *	COACH
 *	COherence Analyzer and CHecker tool for Software-Managed Cache
 *
 *	Description
 *		This program helps programmers to write programs for 
 *		software-managed cache coherence even on the machine with 
 *		hardware-managed cache coherence.
 *		COACH reports cache coherence violations during execution, 
 *		and shows where the program makes violations.
 *		COACH also suggests potential code enhancement for performance improvements.
 *
 *	History
 *		started from Jun 3, 2012
 *		last updated on Mar 15, 2014
 *
 *	Author
 *		written by Kim, Wooil
 *		kim844@illinois.edu
 *
 */


// currently, instruction instrumentation is disabled to see if how many barrier epochs are generated during execution.
// You need to remove comment in main function to enable original COACH function.


// Usage recommendation
// for 

#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define __64BIT__
//	Maximum worker threads are set to 8 now.
#define MAX_WORKER	8
//	Maximum threads are maximum work threads + 1 to support master-workers execution model.
#define MAX_THREADS MAX_WORKER+1
#define STATE_BITS	2
#define MAX_STATES  (MAX_THREADS)*(STATE_BITS)

#define WORD_BITWIDTH	32
#define WORD_BYTES		4
//	4-byte word is assumed.

#define MAX_NESTED_LOCK 5

const char *configFileName = "coach.cfg";



//	Currently all operations are verified with 64-bit only.
#if __WORDSIZE == 64
	#define INT_SIZE	8
	#define WORD_SIZE	4
	#define ADDR_MASK	0xFFFFFFFFFFFFFFFC
#else
	// [TODO] 32-bit execution is not verified yet.
	// Probably, virtual machine platform can be used for 32-bit.
	#define INT_SIZE	4
	#define WORD_SIZE	4
	#define ADDR_MASK	0xFFFFFFFC
#endif


#define	LINE_SIZE	64
#define	PAD_SIZE	(LINE_SIZE - INT_SIZE)


using namespace std;


//-------------------------------------------------------------------
//	Logger
//-------------------------------------------------------------------
//
//	WindyLogger is used for displaying all logging/debugging/error messages.
//	It has seven display levels for both display (stdout) and output file.
//	When display level is set to WARNING, warning or higher level messages 
//	(error, special messages) are sent to stdout. Lower-level messages are 
//	not shown.
//
//	Ordinary types of display levels are extended debug, debug, log, warning, 
//	and error. Special message is used for checking temporarilly required messages 
//	while maintaining ordinary display level. For example, a programmer 
//	needs to see only error message on the display. But, in order to check 
//	recently-added functionality, he wants to add one more message to the 
//	display. This is not an error, but a debug message. Rather than making 
//	this message 'debug', the programmer can set this as 'temporary'.
//	After checking the functionality works fine, the programmer can set 
//	the message as 'debug'. Then, the message will be shown only for the 
//	configuration 'debug' or lower level.

class WindyLogger
{
private:
	int		displayLevel;
	int		fileoutLevel;
	FILE*	outputFile;

public:
	enum DisplayLevelEnum {
		DISPLAY_EXT_DEBUG,		// Debugging information which will be used temporarily.
		DISPLAY_DEBUG,
		DISPLAY_LOG,
		DISPLAY_WARNING,
		DISPLAY_ERROR,
		DISPLAY_TEMP,
		DISPLAY_NONE			// At this level, any message is not displayed.
	};

	enum FileoutLevelEnum {
		FILEOUT_EXT_DEBUG,		// Debugging information which will be used temporarily.
		FILEOUT_DEBUG,
		FILEOUT_LOG,
		FILEOUT_WARNING,
		FILEOUT_ERROR,
		FILEOUT_TEMP,
		FILEOUT_NONE			// At this level, any message is not displayed.
	};

	WindyLogger() 
	{
		// default levels
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
	void	close()					{ fprintf(outputFile, "#eof\n"); fflush(outputFile); fclose(outputFile); }


	void ext_debug(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_EXT_DEBUG) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[EXT]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_EXT_DEBUG) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[EXT]  ");
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

	void temp(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_TEMP) {
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

		if (fileoutLevel <= FILEOUT_TEMP) {
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
};	// class WindyLogger

WindyLogger		Logger;



//-------------------------------------------------------------------
//	Data Structure
//-------------------------------------------------------------------
//
//	sourceLocation structure is used for storing source code location.
//	Mostly used in MallocTracker and write location.

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



//-------------------------------------------------------------------
//	Memory Allocation Tracker
//-------------------------------------------------------------------

typedef		map<ADDRINT, int>			addrMapType;
typedef		map<ADDRINT, int>::iterator	addrMapIterator;

class MallocTracker 
{
private:
	//	addrMap and stateMap are mandatory.
	//	variableNameMap is maintained separately,
	//	sourceMap is optional.

	//	Address and size pair is maintained in STL map.
	map<ADDRINT, int>			addrMap;
	map<ADDRINT, int>::iterator	it;

	vector< pair<ADDRINT, int> >			addrVec;
	vector< pair<ADDRINT, int> >::iterator 	it2;

	map<ADDRINT, bitset<MAX_STATES>* >				stateMap;
	map<ADDRINT, bitset<MAX_STATES>* >::iterator	stateIt;

	map<ADDRINT, string>			variableNameMap;
	map<ADDRINT, string>::iterator	variableNameIt;

	map<ADDRINT, struct sourceLocation>				sourceMap;
	map<ADDRINT, struct sourceLocation>::iterator	sourceIt;

public:
	//	Previous information about allocation is used to find where allocated
	//	memory region is assigned. For example, a = malloc(100); is compiled 
	//	to calling malloc function with an argument which has 100, and copying
	//	returned value to the variable a.
	//	WritesMemBefore function tracks this relation and finds returned value
	//	of address and size of malloc call from prevAddr and prevSize.
	ADDRINT		prevAddr;
	int			prevSize;

	MallocTracker() 
	{
		addrMap.clear(); 
		addrVec.clear();
		sourceMap.clear();
		prevAddr = 0;
		prevSize = 0;
	}

	bool hasEntry(ADDRINT addr) { 
		return (addrMap.find(addr) != addrMap.end()); 
	}

	bool isAddrMapEnd(addrMapIterator myIt) 
	{
		return (myIt == addrMap.end());
	}


	void add(ADDRINT addr, int size) 
	{
		//	If we already have the same address as a start address, this is problematic.
		//	sometimes the program exectues malloc twice for some reason, 
		//	this should not be treated as errors.
		if (hasEntry(addr)) {
			if (addrMap[addr] != size) {
				// we assume the same address and size for the memory allocation is
				// doubly-executed memory allocation.
				// But, different size means different allocation request, so that
				// it is considered as something problematic.
				Logger.warn("Memory allocation occurs for the already allocated address: 0x%lx.", addr);
				return;
			}

			// memory allocation for the same address and size is called.
			// For now, just ignore it.

			// [TODO] calloc after malloc initializes the value. 
			// Thus, if we consider the value, we should check it.
			return;
		}

		addrMap[addr] = size;
		addrVec.push_back(make_pair(addr, size));
		prevAddr = addr;
		prevSize = size;

		// Currently, only word-aligned memory allocation is considered.
		bitset<MAX_STATES>	*pState;
		int wordSize = (size+ (WORD_BYTES-1)) / WORD_BYTES;
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


	// to check if addr is within currently allocated memory area
	bool contain2(ADDRINT addr)
	{
		for (it2 = addrVec.begin(); it2 != addrVec.end(); it2++)
		{
			ADDRINT	startAddr, endAddr;

			startAddr = (*it2).first;
			endAddr = startAddr + (*it2).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					return true;
			}
		}
		return false;
	}


	INT32 containIndex(ADDRINT addr)
	{
		INT32	i = 0;
		for (it2 = addrVec.begin(); it2 != addrVec.end(); it2++)
		{
			ADDRINT	startAddr, endAddr;

			startAddr = (*it2).first;
			endAddr = startAddr + (*it2).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					return i;
			}
			i++;
		}
		return -1;
	}



	addrMapIterator containIterator(ADDRINT addr, int size)
	{
		pair < addrMapIterator, bool> insertResult;
		insertResult = addrMap.insert(make_pair(addr, size));
		addrMapIterator myIt;

		if (insertResult.second == true) {
			// inserted, meaning no address was in the map
			// either no heap address or address in the allocated range
			myIt = insertResult.first;

			if (myIt != addrMap.begin()) {
				// *it is not the first
				ADDRINT		startAddr, endAddr;

				myIt--;
				startAddr = myIt->first;
				endAddr = startAddr + myIt->second;

				if (endAddr > addr) {	// within the allocated range
					addrMap.erase(insertResult.first);
					return myIt;					
				}
				else {	// not within the allocated range
					addrMap.erase(insertResult.first);
					return addrMap.end();
				}
			}
			else {
				// *it is the first.
				addrMap.erase(insertResult.first);
				return addrMap.end();
			}
		}
		else {
			// already there. the first address of one allocated range.
			return insertResult.first;
			//return addrMap.end();
		}
	}


	addrMapIterator containIterator2(ADDRINT addr)
	{
		addrMapIterator myIt;
		myIt = addrMap.upper_bound(addr);

		if (addrMap.size() == 0)
			return addrMap.end();

		if (myIt == addrMap.begin()) {
			ADDRINT		startAddr, endAddr;
			startAddr = myIt->first;
			endAddr = startAddr + myIt->second;
			if ((startAddr <= addr) && (endAddr > addr))
				return myIt;					
			else {	// not within the allocated range
				return addrMap.end();
			}
		}
		else {
			ADDRINT		startAddr, endAddr;
			myIt--;
			startAddr = myIt->first;
			endAddr = startAddr + myIt->second;
			if (endAddr > addr) {	// within the allocated range
				return myIt;					
			}
			else {	// not within the allocated range
				return addrMap.end();
			}
		}

	}


	// to provide an offset inside the variable for the given address
	// It is recommended to call getBase with real address which passes contain().
	ADDRINT getBase(ADDRINT addr)
	{
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			ADDRINT	startAddr, endAddr;

			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					return startAddr;
			}
			else
				return -1;
		}
		return -1;
	}


	ADDRINT getBaseIndex(ADDRINT addr, INT32 index)
	{
		ADDRINT startAddr, endAddr;
		startAddr = addrVec[index].first;
		endAddr = startAddr + addrVec[index].second;

		if (startAddr <= addr) {
			if (endAddr > addr)
				return startAddr;
		}
		return -1;
	}

	ADDRINT getBaseIterator(ADDRINT addr, addrMapIterator myIt)
	{
		ADDRINT startAddr, endAddr;
		startAddr = myIt->first;
		endAddr = startAddr + myIt->second;

		if (startAddr <= addr) {
			if (endAddr > addr)
				return startAddr;
		}
		return -1;
	}

	// to provide an offset inside the variable for the given address
	// It is recommended to call getOffset with real address which passes contain().
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


	ADDRINT getOffsetIndex(ADDRINT addr, INT32 index)
	{
		ADDRINT startAddr, endAddr;
		startAddr = addrVec[index].first;
		endAddr = startAddr + addrVec[index].second;

		if (startAddr <= addr) {
			if (endAddr > addr)
				return addr - startAddr;
		}
		return -1;
	}

	ADDRINT getOffsetIterator(ADDRINT addr, addrMapIterator myIt) 
	{
		ADDRINT startAddr, endAddr;
		startAddr = myIt->first;
		endAddr = startAddr + myIt->second;

		if (startAddr <= addr) {
			if (endAddr > addr)
				return addr - startAddr;
		}
		Logger.error("getOffsetIterator: 0x%lx - 0x%lx", startAddr, endAddr);
		return -1;
	}

	bitset<MAX_STATES>* bitVector(ADDRINT addr)
	{
		ADDRINT	startAddr, endAddr;

		startAddr = 0;	// this is for turning off warning message during compilation.
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

		return &( ( (stateMap[startAddr]) )[(addr - startAddr) / WORD_BYTES] );
	}


	bitset<MAX_STATES>* bitVectorIndex(ADDRINT addr, INT32 index)
	{
		ADDRINT	startAddr, endAddr;

		startAddr = addrVec[index].first;
		endAddr = startAddr + addrVec[index].second;
		return &( ( (stateMap[startAddr]) )[(addr - startAddr) / WORD_BYTES] );
	}

	bitset<MAX_STATES>* bitVectorIterator(ADDRINT addr, map<ADDRINT, int>::iterator myIt)
	{
		ADDRINT	startAddr, endAddr;

		startAddr = myIt->first;
		endAddr = startAddr + myIt->second;
		return &( ( (stateMap[startAddr]) )[(addr - startAddr) / WORD_BYTES] );
		// endAddr is not required.
	}

	void inv_all_for_thread(int tid)
	{
		ADDRINT	startAddr, endAddr;

		startAddr = 0;	// this is for turning off warning message.
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			ADDRINT startWordAddress, endWordAddress;

			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			startWordAddress = startAddr & ADDR_MASK;
			endWordAddress = endAddr & ADDR_MASK;

			for (ADDRINT a = startWordAddress; a < endWordAddress; a += WORD_BYTES)
			{
				if ( (* (bitVector(a)) )[tid*2  ] == 1 && 
					 (* (bitVector(a)) )[tid*2+1] == 0     ) {
					// keep dirty state
				}
				else {
					// otherwise, make it invalid
					(* (bitVector(a)) )[tid*2  ] = 0;
					(* (bitVector(a)) )[tid*2+1] = 0;
				}
			}
		}
	}


	void wb_all_for_thread(int tid)
	{
		ADDRINT	startAddr, endAddr;

		startAddr = 0;	// this is for turning off warning message.
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			ADDRINT startWordAddress, endWordAddress;

			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			startWordAddress = startAddr & ADDR_MASK;
			endWordAddress = endAddr & ADDR_MASK;

			for (ADDRINT a = startWordAddress; a < endWordAddress; a += WORD_BYTES)
			{
				bitset<MAX_STATES>* bv;
				bv = bitVectorIterator(a, it);
				if ( (*bv)[tid*2  ] == 1 && 
					 (*bv)[tid*2+1] == 0     ) {
					bv->set();

					// dirty -> clean
					(* (bitVector(a)) )[tid*2  ] = 0;
					(* (bitVector(a)) )[tid*2+1] = 1;				
				}
			}
		}
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

		Logger.log("addVariableName: %s is added as addr 0x%lx.", s.c_str(), prevAddr);
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

	string getVariableNameIndex(INT32 index)
	{
		ADDRINT startAddr;
		startAddr = addrVec[index].first;
		return variableNameMap[startAddr];		
	}

	string getVariableNameIterator(map<ADDRINT, int>::iterator myIt)
	{
		ADDRINT startAddr;
		startAddr = myIt->first;
		if (variableNameMap.find(startAddr) == variableNameMap.end())
			Logger.error("0x%lx fails to find name", startAddr);
		if (startAddr == 0)
			return "noname";
		return variableNameMap[startAddr];
		// [TODO] does myIt itself point to the name?
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
	bitset<MAX_STATES>	*pMallocState;

	GlobalVariableStruct() { }
	GlobalVariableStruct(string s, ADDRINT a, int sz, int aa, int as)
		: name(s), addr(a), size(sz), allocAddr(aa), allocSize(as)
	{
		// [TODO] here, I do not consider word alignment.
		int wordSize = (sz+ (WORD_BYTES-1)) / WORD_BYTES;
		pState = new bitset<MAX_STATES> [wordSize];
		for (int i = 0; i < wordSize; i++)
			pState[i].reset();
		pMallocState = NULL;
	}

	void attachState()
	{
		int wordSize = (allocSize + (WORD_BYTES-1)) / WORD_BYTES;
		pMallocState = new bitset<MAX_STATES> [wordSize];
		for (int i = 0; i < wordSize; i++)
			pMallocState[i].reset();
	}

	void invalidateAll(int tid)
	{
		int wordSize;
		wordSize = (size + (WORD_BYTES-1)) / WORD_BYTES;
		for (int i = 0; i < wordSize; i++)
		{
			if ((pState[i])[tid*2+1] == 1) {
				(pState[i])[tid*2] = 0;
				(pState[i])[tid*2+1] = 0;
			}
		}

		wordSize = (allocSize + (WORD_BYTES-1)) / WORD_BYTES;
		for (int i = 0; i < wordSize; i++)
		{
			if ((pState[i])[tid*2+1] == 1) {
				(pState[i])[tid*2] = 0;
				(pState[i])[tid*2+1] = 0;
			}
		}
	}

	void writebackAll(int tid)
	{
		int wordSize;
		wordSize = (size + (WORD_BYTES-1)) / WORD_BYTES;
		for (int i = 0; i < wordSize; i++)
		{
			if ((pState[i])[tid*2] == 1) {
				(pState[i])[tid*2] = 0;
				(pState[i])[tid*2+1] = 1;
			}
		}

		wordSize = (allocSize + (WORD_BYTES-1)) / WORD_BYTES;
		for (int i = 0; i < wordSize; i++)
		{
			if ((pState[i])[tid*2] == 1) {
				(pState[i])[tid*2] = 0;
				(pState[i])[tid*2+1] = 1;
			}
		}
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
	writeFirst,
	writeDiscard
};

enum ProgramCategory {
	UNKNOWN,
	PTHREAD,
	GTHREAD,
	OPENMP
};


enum LockedState {
	DuringLockFunc,
	Unlocked,
	Locked1,
	Locked2,
	Locked3,
	Locked4,
	Locked5			// we set MAX_NESTED_LOCK as 5
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
char			VariableFileName[200];
BOOL			ExcludePotentialSystemVariables;	// if true, global variable which name starts with '.' or '_' is ignored.

//	tracking configuration
BOOL			AfterMainTracking;			// if true, address tracking is enabled after main function is started
BOOL			MainRunning;				// after main function is started, this is set as true.
BOOL			MasterThreadOnlyAllocFree;	// if true, memory allocation/free from child threads is not tracked
BOOL			SrcWriteTracking;
BOOL			SrcReadTracking;



PIN_LOCK		Lock;

INT				NumThreads;					// Current number of threads
INT				MaxThreads;					// Maximum number of threads appeared during execution
UINT			BarrierCount;				// How many barrier region appeared
INT				BarrierNumber;				// How many participants for this barrier
INT				CurrentBarrierArrival;		// For tracking currently arrived participants for the barrier
INT				SegmentCount[MAX_THREADS];

BOOL			AutoInvForLock[MAX_THREADS];
BOOL			AutoInvForEpoch[MAX_THREADS];
BOOL			CheckEnabled;

MallocTracker	MATracker;

std::map<ADDRINT, std::string>	DisAssemblyMap;
struct thread_data_t	NumReads[MAX_THREADS];
struct thread_data_t	NumWrites[MAX_THREADS];

BOOL			AfterAlloc[MAX_THREADS];	// if true, it is just after memory allocation function.
ADDRINT			StackBase[MAX_THREADS];
ADDRINT			StackPointer[MAX_THREADS];

//list<ADDRINT>	WrittenWordsInThisEpoch[MAX_THREADS];
set<ADDRINT>	WrittenWordsInThisEpoch[MAX_THREADS];
//list<ADDRINT>::iterator	WrittenWordsIterator[MAX_THREADS];
set<ADDRINT>::iterator	WrittenWordsIterator[MAX_THREADS];

map<ADDRINT, int> WrittenBackInThisEpoch[MAX_THREADS];
map<ADDRINT, int>::iterator WrittenBackIterator[MAX_THREADS];


//	Global Variable Vector
//	State definition
//	00 means invalid state
//	01 means clean state
//	10 means modified state
//	11 means stale state
vector<struct GlobalVariableStruct>	GlobalVariableVec;
vector<struct GlobalVariableStruct>::iterator	GlobalVariableVecIterator;
typedef map<ADDRINT, struct GlobalVariableStruct>	gvmap;
gvmap												GlobalVariableMap;
typedef gvmap::iterator								gvmapit;
gvmapit												GlobalVariableMapIterator;


//	This is not enough for tracking many lock variables.
//	For only checking single lock variable, MutexLocked is used.
int				MutexLocked[MAX_THREADS];
void*			MutexLock[MAX_THREADS][MAX_NESTED_LOCK];
BOOL			DuringBarrierFunc[MAX_THREADS];
BOOL			DuringCondFunc[MAX_THREADS];

//list<ADDRINT>	WrittenWordsInThisLock[MAX_THREADS];
set<ADDRINT>	WrittenWordsInThisLock[MAX_THREADS];
map<ADDRINT, int> WrittenBackInThisLock[MAX_THREADS];

//	Vector Lock
vector<ADDRINT>	LockVector;
ADDRINT			MinLockVector;
ADDRINT			MaxLockVector;

// tracking program flow
ADDRINT			beforeBranch[MAX_THREADS];


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

gvmapit isGlobalVariableIterator(ADDRINT addr)
{
	gvmapit		it;
	it = GlobalVariableMap.upper_bound(addr);

	if (GlobalVariableMap.size() == 0)
		return GlobalVariableMap.end();

	if (it == GlobalVariableMap.begin()) {
		ADDRINT		startAddr, endAddr;
		startAddr = it->first;
		endAddr = startAddr + it->second.size;

		if ((startAddr <= addr) && (endAddr > addr))
			return it;
		else // not within this global variable
			return GlobalVariableMap.end();
	}
	else {
		ADDRINT		startAddr, endAddr;
		it--;
		startAddr = it->first;
		endAddr = startAddr + it->second.size;
		if (endAddr > addr)
			return it;
		else
			return GlobalVariableMap.end();
	}
}


gvmapit isGlobalVariableIteratorDebug(ADDRINT addr)
{
	gvmapit		it;
	it = GlobalVariableMap.upper_bound(addr);

	if (GlobalVariableMap.size() == 0) 
	{
		Logger.error("0x%lx has case 1", addr);
		return GlobalVariableMap.end();
	}

	if (it == GlobalVariableMap.begin()) {
		ADDRINT		startAddr, endAddr;
		startAddr = it->first;
		endAddr = startAddr + it->second.size;

		if ((startAddr <= addr) && (endAddr > addr))
			return it;
		else // not within this global variable
		{
			Logger.error("0x%lx has case 2", addr);			
			return GlobalVariableMap.end();
		}
	}
	else {
		ADDRINT		startAddr, endAddr;
		it--;
		startAddr = it->first;
		endAddr = startAddr + it->second.size;
		if (endAddr > addr)
			return it;
		else {
			Logger.error("0x%lx has case 3", addr);
			return GlobalVariableMap.end();
		}
	}
}


//	Calculate the offset within global variable
//	The address should be for global variable. If not, -1 will be returned.
ADDRINT baseInGlobalVariable(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			return (*it).addr;
		if ( (addr >= (*it).addr) && (addr < (*it).addr + (*it).size) )
			return (*it).addr;
	}
	// This must not happen.
	return -1;
}


ADDRINT baseInGlobalVariableIterator(ADDRINT addr, gvmapit it)
{
	ADDRINT startAddr, endAddr;
	startAddr = it->first;
	endAddr = startAddr + it->second.size;

	if (startAddr <= addr) {
		if (endAddr > addr)
			return startAddr;
	}
	return -1;
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

ADDRINT offsetInGlobalVariableIterator(ADDRINT addr, gvmapit it)
{
	ADDRINT startAddr, endAddr;
	startAddr = it->first;
	endAddr = startAddr + it->second.size;

	if (startAddr <= addr) {
		if (endAddr > addr)
			return addr - startAddr;
	}
	Logger.error("getOffsetIterator: 0x%lx - 0x%lx", startAddr, endAddr);
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
			return &((*it).pState[(addr-(*it).addr) / WORD_BYTES]);
	}

	Logger.error("No match in bitVectorForGlobalVariable (end or overrun) addr = 0x%lx", addr);
	Logger.error("List of global variables");
	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		Logger.error("addr=0x%lx, size=%d", (*it).addr, (*it).size);
	}

	return NULL;
}


bitset<MAX_STATES>* bitVectorForGlobalVariableIterator(ADDRINT addr, gvmapit it)
{
	ADDRINT	startAddr;

	startAddr = it->first;
	return &( (it->second).pState[(addr - startAddr) / WORD_BYTES] );
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

const char* getGlobalVariableNameIterator(gvmapit it)
{
	return (it->second).name.c_str();
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
		Logger.warn("[tid: %d] malloc failed.", tid);
	AfterAlloc[tid] = true;
	
	ReleaseLock(&Lock);
	Logger.log("after malloc");
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

	Logger.warn("[tid: %d] realloc is called for %p, but not supported completely for now.", tid, ptr);

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
	Logger.log("[tid: %d] realloc with ptr %p, size %d returns 0x%lx\n", tid, ptr, size, (ADDRINT) ret);

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
	Logger.log("[tid: %d] free with ptr %p returns.\n", tid, ptr);

	// remove call is moved forward to prevent some wierd writes during free() call.
	//MATracker.remove((ADDRINT) ptr);
	ReleaseLock(&Lock);

	return ret;
}


//---------------------------------------------------------
//	PMC Functions
//	coherence-management functions
//---------------------------------------------------------

//	pre-declaration
VOID ReadsMemBefore (ADDRINT applicationIp, THREADID tid, ADDRINT memoryAddressRead, UINT32 memoryReadSize, ADDRINT sp);
VOID WritesMemBefore(ADDRINT applicationIp, THREADID tid, ADDRINT memoryAddressWrite, UINT32 memoryWriteSize, ADDRINT sp);



void PMC_coherence(PMCInst function, int tid, ADDRINT addr, int size)
{
	// Range check for writebacks
	// This is for checking redundant writeback, leading to performance bugs.
	// if new writeback address overlaps previous writeback range in this epoch,
	// this is overlap, which should be informed to the programmer.
	// if not overlap, new address range is added to writeback map.

	gvmapit myIt;

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
		/*
		if (isGlobalVariable(addr)) {
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += WORD_BYTES)
			{
				Logger.ext_debug("[tid: %d] addr2 = %lx", tid, addr2);
				if (bitVectorForGlobalVariable(addr2) == 0)
					//break;
					continue;
				if ( (* (bitVectorForGlobalVariable(addr2)) )[tid*2] == 0 &&
					 (* (bitVectorForGlobalVariable(addr2)) )[tid*2+1] == 0 ) {
					Logger.ext_debug("no wb from virgin");
					continue;
				}
				if ( (* (bitVectorForGlobalVariable(addr2)) )[tid*2] == 0 &&
					 (* (bitVectorForGlobalVariable(addr2)) )[tid*2+1] == 1 ) {
					Logger.ext_debug("no wb from read valid");
					continue;
				}
				if ( (* (bitVectorForGlobalVariable(addr2)) )[tid*2] == 1 &&
					 (* (bitVectorForGlobalVariable(addr2)) )[tid*2+1] == 1 ) {
					//Logger.error("[tid: %d] stale data is written-back. addr=0x%lx", tid, addr2);
					Logger.ext_debug("no wb because this is stale");
					continue;
				}
				for (int i = 0; i < MAX_THREADS; i++)
				{
					Logger.ext_debug("i = %d", i);
					Logger.ext_debug("bitvector = %lx", bitVectorForGlobalVariable(addr2));
					if (tid == i)	continue;

					if ( (* (bitVectorForGlobalVariable(addr2)) )[i*2] == 0 &&
						 (* (bitVectorForGlobalVariable(addr2)) )[i*2+1] == 1 ) {
						Logger.ext_debug("case 1");
						// 00 means unloaded state
						// 01 means read valid state **
						// 10 means write valid state
						// 11 means stale state
						(* (bitVectorForGlobalVariable(addr2)) )[i*2  ] = 1;
						(* (bitVectorForGlobalVariable(addr2)) )[i*2+1] = 1;
					}
					else if ( (* (bitVectorForGlobalVariable(addr2)) )[i*2] == 1 &&
							 (* (bitVectorForGlobalVariable(addr2)) )[i*2+1] == 0 ) {
						Logger.ext_debug("case 2");
						// 00 means unloaded state
						// 01 means read valid state
						// 10 means write valid state **
						// 11 means stale state
						(* (bitVectorForGlobalVariable(addr2)) )[i*2  ] = 1;
						(* (bitVectorForGlobalVariable(addr2)) )[i*2+1] = 1;
						// [TODO] check this is required, or this has potential issues.
						// if other processor has write valid state, this may have potential violation.
						Logger.error("[tid: %d] writeback occurs on other core(%d)'s dirty data: addr 0x%lx, name: %s, base=0x%lx, offset=0x%x", 
							tid, i, addr2, getGlobalVariableName(addr2), baseInGlobalVariable(addr2), offsetInGlobalVariable(addr2));
					}
					// Added the case of unloaded state, assuming possible load of multi-line cache
					else if ( (* (bitVectorForGlobalVariable(addr2)) )[i*2] == 0 &&
							 (* (bitVectorForGlobalVariable(addr2)) )[i*2+1] == 0 ) {
						Logger.ext_debug("case 2 for 0x%lx", addr2);
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
				Logger.ext_debug("case 3");
				// Guess the following is already done in WritesMemBefore.
				(* (bitVectorForGlobalVariable(addr2)) )[tid * 2] = 0;
				(* (bitVectorForGlobalVariable(addr2)) )[tid * 2+1] = 1;
				Logger.ext_debug("[tid: %d] writeback to 0x%lx makes all other threads' state as stale.", tid, addr2);
			}
		}
		*/
		myIt = isGlobalVariableIterator(addr);
		if (myIt != GlobalVariableMap.end()) {
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += WORD_BYTES)
			{
				Logger.ext_debug("[tid: %d] addr2 = %lx", tid, addr2);
				if (bitVectorForGlobalVariableIterator(addr2, myIt) == 0)
					//break;
					continue;
				if ( (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid*2] == 0 &&
					 (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid*2+1] == 0 ) {
					Logger.ext_debug("no wb from virgin");
					continue;
				}
				if ( (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid*2] == 0 &&
					 (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid*2+1] == 1 ) {
					Logger.ext_debug("no wb from read valid");
					continue;
				}
				if ( (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid*2] == 1 &&
					 (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid*2+1] == 1 ) {
					//Logger.error("[tid: %d] stale data is written-back. addr=0x%lx", tid, addr2);
					Logger.ext_debug("no wb because this is stale");
					continue;
				}
				for (int i = 0; i < MAX_THREADS; i++)
				{
					Logger.ext_debug("i = %d", i);
					Logger.ext_debug("bitvector = %lx", bitVectorForGlobalVariableIterator(addr2, myIt));
					if (tid == i)	continue;

					if ( (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2] == 0 &&
						 (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2+1] == 1 ) {
						Logger.ext_debug("case 1");
						// 00 means unloaded state
						// 01 means read valid state **
						// 10 means write valid state
						// 11 means stale state
						(* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2  ] = 1;
						(* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2+1] = 1;
					}
					else if ( (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2] == 1 &&
							  (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2+1] == 0 ) {
						Logger.ext_debug("case 2");
						// 00 means unloaded state
						// 01 means read valid state
						// 10 means write valid state **
						// 11 means stale state
						(* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2  ] = 1;
						(* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2+1] = 1;
						// [TODO] check this is required, or this has potential issues.
						// if other processor has write valid state, this may have potential violation.
						Logger.error("[tid: %d] writeback occurs on other core(%d)'s dirty data: addr 0x%lx, name: %s, base=0x%lx, offset=0x%x", 
							tid, i, addr2, getGlobalVariableNameIterator(myIt), baseInGlobalVariableIterator(addr2, myIt), offsetInGlobalVariableIterator(addr2, myIt));
					}
					// Added the case of unloaded state, assuming possible load of multi-line cache
					else if ( (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2] == 0 &&
							 (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2+1] == 0 ) {
						Logger.ext_debug("case 2 for 0x%lx", addr2);
						// 00 means unloaded state
						// 01 means read valid state
						// 10 means write valid state **
						// 11 means stale state
						(* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2  ] = 1;
						(* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[i*2+1] = 1;
						// [TODO] check this is required, or this has potential issues.
						// if other processor has write valid state, this may have potential violation.
					}
				}
				Logger.ext_debug("case 3");
				// Guess the following is already done in WritesMemBefore.
				(* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid * 2] = 0;
				(* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid * 2+1] = 1;
				Logger.ext_debug("[tid: %d] writeback to 0x%lx makes all other threads' state as stale.", tid, addr2);
			}
		}
		else if (MATracker.contain(addr)) {
			// [TODO] fill this!!!
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += WORD_BYTES)
			{
				if ( (* (MATracker.bitVector(addr2)) )[tid * 2] == 0 &&
					 (* (MATracker.bitVector(addr2)) )[tid * 2+1] == 0 ) {
					continue;
				}
				if ( (* (MATracker.bitVector(addr2)) )[tid * 2] == 0 &&
					 (* (MATracker.bitVector(addr2)) )[tid * 2+1] == 1 ) {
					continue;
				}
				if ( (* (MATracker.bitVector(addr2)) )[tid*2] == 1 &&
					 (* (MATracker.bitVector(addr2)) )[tid*2+1] == 1 ) {
					//Logger.error("[tid: %d] stale data is written-back. addr=0x%lx", tid, addr2);
					continue;
				}
				for (int i = 0; i < MAX_THREADS; i++)
				{
					if (tid == i) continue;
					if ( (* (MATracker.bitVector(addr2)) )[i*2  ] == 1 &&
						 (* (MATracker.bitVector(addr2)) )[i*2+1] == 0    )
						Logger.error("[tid: %d] writeback occurs on other core(%d)'s dirty data: addr 0x%lx, name: %s, base=0x%lx, offset=0x%x", 
							tid, i, addr2, MATracker.getVariableName(addr2).c_str(), MATracker.getBase(addr2), MATracker.getOffset(addr2));

					// currently, for all cases, make other threads' state 'stale'
					//if ( (* (MATracker.bitVector(addr2)) )[i*2+1] == 1 ) {
						// 00 means unloaded state
						// 01 means read valid state
						// 10 means write valid state
						// 11 means stale state
						(* (MATracker.bitVector(addr2)) )[i*2  ] = 1;
						(* (MATracker.bitVector(addr2)) )[i*2+1] = 1;
					//}

				}
				(* (MATracker.bitVector(addr2)) )[tid * 2] = 0;
				(* (MATracker.bitVector(addr2)) )[tid * 2+1] = 1;
				Logger.ext_debug("[tid: %d] writeback to 0x%lx makes all other threads' state as stale.", tid, addr2);
			}
		}
	}

	if ((function == invalidation) || (function == writebackInvalidation)) {
		// [TODO] Check if this is for the latest data
		// [TODO] consider size. may need to be included in for loop.
		/*
		if (isGlobalVariable(addr)) {
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += WORD_BYTES)
			{
				if ( (* (bitVectorForGlobalVariable(addr2)) )[tid * 2] != 1 ||
					 (* (bitVectorForGlobalVariable(addr2)) )[tid * 2+1] != 0 ) {
					(* (bitVectorForGlobalVariable(addr2)) )[tid * 2] = 0;
					(* (bitVectorForGlobalVariable(addr2)) )[tid * 2+1] = 0;
					Logger.ext_debug("[tid: %d] invalidation to 0x%lx makes this threads' state as invalid.", tid, addr2);
				}
			}
		}
		*/
		myIt = isGlobalVariableIterator(addr);
		if (myIt != GlobalVariableMap.end()) {
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += WORD_BYTES)
			{
				if ( (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid * 2] != 1 ||
					 (* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid * 2+1] != 0 ) {
					(* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid * 2] = 0;
					(* (bitVectorForGlobalVariableIterator(addr2, myIt)) )[tid * 2+1] = 0;
					Logger.ext_debug("[tid: %d] invalidation to 0x%lx makes this threads' state as invalid.", tid, addr2);
				}
			}
		}
		else if (MATracker.contain(addr)) {
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += WORD_BYTES)
			{
				if ( (* (MATracker.bitVector(addr2)) )[tid * 2] != 1 ||
					 (* (MATracker.bitVector(addr2)) )[tid * 2+1] != 0 ) {
					(* (MATracker.bitVector(addr2)) )[tid * 2] = 0;
					(* (MATracker.bitVector(addr2)) )[tid * 2+1] = 0;
					Logger.ext_debug("[tid: %d] invalidation to 0x%lx makes this threads' state as invalid.", tid, addr2);
				}
			}
		}
	}
}

void PMC_process(PMCInst function, int tid, ADDRINT addr, int size)
{
	ADDRINT startWordAddress, endWordAddress, offset;
	ADDRINT offsetMask = 0x3;					// WORD_BYTES - 1;

	startWordAddress = addr & ADDR_MASK;
	endWordAddress = (addr + size) & ADDR_MASK;
	offset = addr & offsetMask;

	gvmapit	myIt;


	// _all
	if ((addr == 0) && (size == 1)) {
		switch (function) {
		case invalidation:
			if (MutexLocked[tid] >= Locked1) {
				AutoInvForLock[tid] = true;
				// will be cleared in unlockWrapper
				Logger.log("[tid: %d] inv all for the lock", tid);
			}
			else if (MutexLocked[tid] == Unlocked) {

				/*
				for (GlobalVariableVecIterator = GlobalVariableVec.begin();
					 GlobalVariableVecIterator != GlobalVariableVec.end();
					 ++GlobalVariableVecIterator)
				{
					PMC_coherence(function, tid, (*GlobalVariableVecIterator).addr, (*GlobalVariableVecIterator).size);
				}

				MATracker.inv_all_for_thread(tid);
				*/

				AutoInvForEpoch[tid] = true;
				// will be cleared in next barrierWrapper
				Logger.log("[tid: %d] inv all", tid);
			}
			break;

		case writeback:
		case writebackInvalidation:
			// set implementation
			if (MutexLocked[tid] >= Locked1) {
				for (WrittenWordsIterator[tid] = WrittenWordsInThisLock[tid].begin();
					WrittenWordsIterator[tid] != WrittenWordsInThisLock[tid].end();
					WrittenWordsIterator[tid]++)
					PMC_coherence(function, tid, *WrittenWordsIterator[tid], 4);

				WrittenWordsInThisLock[tid].clear();
				Logger.log("[tid: %d] wb all for the lock", tid);
			}
			else if (MutexLocked[tid] == Unlocked) {
				for (WrittenWordsIterator[tid] = WrittenWordsInThisEpoch[tid].begin();
					WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end();
					WrittenWordsIterator[tid]++)
					PMC_coherence(function, tid, *WrittenWordsIterator[tid], 4);				
				
				// global variables
				// and allocated memory
				//MATracker.wb_all_for_thread(tid);
				WrittenWordsInThisEpoch[tid].clear();
				Logger.log("[tid: %d] wb all", tid);
			}
			break;
		default:
			break;
		}
		return ;
	}

	// master_all
	if ((addr == 0) && (size == 2)) {
		switch (function) {
		case invalidation:
			if (MutexLocked[tid] >= Locked1) {
				AutoInvForLock[tid] = true;
				// will be cleared in unlockWrapper
			}
			else if (MutexLocked[tid] == Unlocked) {
				AutoInvForEpoch[tid] = true;
				// will be cleared in next barrierWrapper
			}
			break;

		case writeback:
		case writebackInvalidation:
			// set implementation
			if (MutexLocked[tid] >= Locked1) {
				for (WrittenWordsIterator[tid] = WrittenWordsInThisLock[tid].begin();
					WrittenWordsIterator[tid] != WrittenWordsInThisLock[tid].end();
					WrittenWordsIterator[tid]++)
				{
					// for master all, written results are changed to read valid state.
					// all other threads' states remain the same.
					ADDRINT	a = *WrittenWordsIterator[tid];
					/*
					if (isGlobalVariable(a)) {
						(* (bitVectorForGlobalVariable(a)) )[tid*2  ] = 0;
						(* (bitVectorForGlobalVariable(a)) )[tid*2+1] = 1;
					}
					else if (MATracker.contain(a)) {
						(* (MATracker.bitVector(a)) )[tid*2  ] = 0;
						(* (MATracker.bitVector(a)) )[tid*2+1] = 1;
					}
					*/
					myIt = isGlobalVariableIterator(a);
					if (myIt != GlobalVariableMap.end()) {
						(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2  ] = 0;
						(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] = 1;
					}
					else if (MATracker.contain(a)) {
						(* (MATracker.bitVector(a)) )[tid*2  ] = 0;
						(* (MATracker.bitVector(a)) )[tid*2+1] = 1;
					}
					else {
						Logger.error("[tid: %d] wb_master_all cannot find address 0x%lx in either global or malloc area.",
							tid, a);
					}
				}

				WrittenWordsInThisLock[tid].clear();
				Logger.log("[tid: %d] wb master all for the lock", tid);
			}
			else {
				// if the following is used, wb_master_all is the same as wb_all.
				//for (WrittenWordsIterator[tid] = WrittenWordsInThisEpoch[tid].begin();
				//	WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end();
				//	WrittenWordsIterator[tid]++)
				//	PMC_coherence(function, tid, *WrittenWordsIterator[tid], 4);				

				for (WrittenWordsIterator[tid] = WrittenWordsInThisEpoch[tid].begin();
					WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end();
					WrittenWordsIterator[tid]++)
				{
					// for master all, written results are changed to read valid state.
					// all other threads' states remain the same.
					ADDRINT	a = *WrittenWordsIterator[tid];
					/*
					if (isGlobalVariable(a)) {
						(* (bitVectorForGlobalVariable(a)) )[tid*2  ] = 0;
						(* (bitVectorForGlobalVariable(a)) )[tid*2+1] = 1;
					}
					else if (MATracker.contain(a)) {
						(* (MATracker.bitVector(a)) )[tid*2  ] = 0;
						(* (MATracker.bitVector(a)) )[tid*2+1] = 1;
					}
					*/
					myIt = isGlobalVariableIterator(a);
					if (myIt != GlobalVariableMap.end()) {
						(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2  ] = 0;
						(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] = 1;
					}
					else if (MATracker.contain(a)) {
						(* (MATracker.bitVector(a)) )[tid*2  ] = 0;
						(* (MATracker.bitVector(a)) )[tid*2+1] = 1;
					}
					else {
						Logger.error("[tid: %d] wb_master_all cannot find address 0x%lx in either global or malloc area.",
							tid, a);
					}
				}

				WrittenWordsInThisEpoch[tid].clear();
				Logger.log("[tid: %d] wb master all", tid);				
			}
			break;
		default:
			break;
		}

		return ;
	}

	for (ADDRINT a = startWordAddress; a + offset < endWordAddress; a += WORD_BYTES)
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
			Logger.ext_debug("writeback starts.");

			/*
			for (WrittenWordsIterator[tid] = WrittenWordsInThisEpoch[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end(); WrittenWordsIterator[tid]++)
			{
				Logger.ext_debug("checking written word 0x%lx", *WrittenWordsIterator[tid]);
				if (a == *WrittenWordsIterator[tid]) {
					Logger.ext_debug("Found in written words list, for writeback addr= 0x%lx, size = %d", addr, size);
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
					Logger.ext_debug("vector size decreases from %d to %d", temp_size, WrittenWordsInThisEpoch[tid].size());
					break;
				}
			}
			*/
			// set implementation
			if (MutexLocked[tid] >= Locked1)
				WrittenWordsInThisLock[tid].erase(a);
			else
				WrittenWordsInThisEpoch[tid].erase(a);
			Logger.ext_debug("writeback ends for %x.", a);
			Logger.ext_debug("[tid: %d] writeback ends for word 0x%x.", tid, a);
			break;
			//LC[tid].cleanEntry(a);  break;

		case writebackInvalidation:
			//LC[tid].cleanEntry(a);  LC[tid].removeEntry(a);  break;
			// like writeback
			Logger.ext_debug("writeback and invalidation starts.");
			if (MutexLocked[tid] >= Locked1)
				WrittenWordsInThisLock[tid].erase(a);
			else
				WrittenWordsInThisEpoch[tid].erase(a);
			Logger.ext_debug("writeback and invalidation ends.");
			break;


		case loadBypass:
			Logger.ext_debug("loadBypass starts.");
			ReadsMemBefore((ADDRINT) 0, tid, addr, size, 0);
			Logger.ext_debug("loadBypass ends.");
			break;

		case storeBypass:
			Logger.ext_debug("storeBypass starts.");
			WritesMemBefore(0, tid, addr, size, 0);
			Logger.ext_debug("storeBypass ends.");
			break;

		case writebackMerge:
			// writebackMerge is completely the same as writeback.
			// Because this is traffic-optimization, does not change semantics.
			Logger.ext_debug("writeback_merge starts.");
			// set implementation
			WrittenWordsInThisEpoch[tid].erase(a);
			Logger.ext_debug("writeback_merge ends.");
			break;

		case writebackReserve:
			Logger.ext_debug("writeback_reserve starts.");
			Logger.ext_debug("writeback_reserve ends.");

			break;

		case writeFirst:
			// make the region as invalid to check write first.
			Logger.ext_debug("writefirst starts.");

			Logger.ext_debug("writefirst ends.");
			break;

		default:
			// not yet implemented
			break;
		}
	}

	PMC_coherence(function, tid, addr, size);
	/*
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
			for (addr2 = addr; addr2 < addr + size; addr2 += WORD_BYTES)
			{
				Logger.ext_debug("[tid: %d] addr2 = %lx", tid, addr2);
				if (bitVectorForGlobalVariable(addr2) == 0)
					//break;
					continue;
				if ( (* (bitVectorForGlobalVariable(addr2)) )[tid*2] == 0 &&
					 (* (bitVectorForGlobalVariable(addr2)) )[tid*2+1] == 0 ) {
					continue;
				}
				if ( (* (bitVectorForGlobalVariable(addr2)) )[tid*2] == 0 &&
					 (* (bitVectorForGlobalVariable(addr2)) )[tid*2+1] == 1 ) {
					continue;
				}
				if ( (* (bitVectorForGlobalVariable(addr2)) )[tid*2] == 1 &&
					 (* (bitVectorForGlobalVariable(addr2)) )[tid*2+1] == 1 ) {
					//Logger.error("[tid: %d] stale data is written-back. addr=0x%lx", tid, addr2);
					continue;
				}
				for (int i = 0; i < MAX_THREADS; i++)
				{
					Logger.ext_debug("i = %d", i);
					Logger.ext_debug("bitvector = %lx", bitVectorForGlobalVariable(addr2));
					if ( (* (bitVectorForGlobalVariable(addr2)) )[i*2] == 0 &&
						 (* (bitVectorForGlobalVariable(addr2)) )[i*2+1] == 1 ) {
						Logger.ext_debug("case 1");
						// 00 means unloaded state
						// 01 means read valid state **
						// 10 means write valid state
						// 11 means stale state
						(* (bitVectorForGlobalVariable(addr2)) )[i*2  ] = 1;
						(* (bitVectorForGlobalVariable(addr2)) )[i*2+1] = 1;
					}
					else if ( (* (bitVectorForGlobalVariable(addr2)) )[i*2] == 1 &&
							 (* (bitVectorForGlobalVariable(addr2)) )[i*2+1] == 0 ) {
						Logger.ext_debug("case 2");
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
						Logger.ext_debug("case 2");
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
				Logger.ext_debug("case 3");
				// Guess the following is already done in WritesMemBefore.
				(* (bitVectorForGlobalVariable(addr2)) )[tid * 2] = 0;
				(* (bitVectorForGlobalVariable(addr2)) )[tid * 2+1] = 1;
				Logger.ext_debug("[tid: %d] writeback to 0x%lx makes all other threads' state as stale.", tid, addr2);
			}
		}
		else if (MATracker.contain(addr)) {
			// [TODO] fill this!!!
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += WORD_BYTES)
			{
				if ( (* (MATracker.bitVector(addr2)) )[tid * 2] == 0 &&
					 (* (MATracker.bitVector(addr2)) )[tid * 2+1] == 0 ) {
					continue;
				}
				if ( (* (MATracker.bitVector(addr2)) )[tid * 2] == 0 &&
					 (* (MATracker.bitVector(addr2)) )[tid * 2+1] == 1 ) {
					continue;
				}
				if ( (* (MATracker.bitVector(addr2)) )[tid*2] == 1 &&
					 (* (MATracker.bitVector(addr2)) )[tid*2+1] == 1 ) {
					//Logger.error("[tid: %d] stale data is written-back. addr=0x%lx", tid, addr2);
					continue;
				}
				for (int i = 0; i < MAX_THREADS; i++)
				{
					// currently, for all cases, make other threads' state 'stale'
					//if ( (* (MATracker.bitVector(addr2)) )[i*2+1] == 1 ) {
						// 00 means unloaded state
						// 01 means read valid state
						// 10 means write valid state
						// 11 means stale state
						(* (MATracker.bitVector(addr2)) )[i*2  ] = 1;
						(* (MATracker.bitVector(addr2)) )[i*2+1] = 1;
					//}
				}
				(* (MATracker.bitVector(addr2)) )[tid * 2] = 0;
				(* (MATracker.bitVector(addr2)) )[tid * 2+1] = 1;
				Logger.ext_debug("[tid: %d] writeback to 0x%lx makes all other threads' state as stale.", tid, addr2);
			}
		}
	}

	if ((function == invalidation) || (function == writebackInvalidation)) {
		// [TODO] Check if this is for the latest data
		// [TODO] consider size. may need to be included in for loop.
		if (isGlobalVariable(addr)) {
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += WORD_BYTES)
			{
				if ( (* (bitVectorForGlobalVariable(addr2)) )[tid * 2] != 1 ||
					 (* (bitVectorForGlobalVariable(addr2)) )[tid * 2+1] != 0 ) {
					(* (bitVectorForGlobalVariable(addr2)) )[tid * 2] = 0;
					(* (bitVectorForGlobalVariable(addr2)) )[tid * 2+1] = 0;
					Logger.ext_debug("[tid: %d] invalidation to 0x%lx makes this threads' state as invalid.", tid, addr2);
				}
			}
		}
		else if (MATracker.contain(addr)) {
			ADDRINT	addr2;
			for (addr2 = addr; addr2 < addr + size; addr2 += WORD_BYTES)
			{
				if ( (* (MATracker.bitVector(addr2)) )[tid * 2] != 1 ||
					 (* (MATracker.bitVector(addr2)) )[tid * 2+1] != 0 ) {
					(* (MATracker.bitVector(addr2)) )[tid * 2] = 0;
					(* (MATracker.bitVector(addr2)) )[tid * 2+1] = 0;
					Logger.ext_debug("[tid: %d] invalidation to 0x%lx makes this threads' state as invalid.", tid, addr2);
				}
			}
		}
	}
	*/
}


// Invalidation
VOID inv_word(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] inv_word -> addr %p", tid, addr);
	PMC_process(invalidation, tid, (ADDRINT) addr, 4);
	ReleaseLock(&Lock);
	return;
}


VOID inv_dword(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] inv_dword -> addr %p", tid, addr);
	PMC_process(invalidation, tid, (ADDRINT) addr, 8);
	ReleaseLock(&Lock);
	return;
}


VOID inv_qword(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] inv_qword -> addr %p", tid, addr);
	PMC_process(invalidation, tid, (ADDRINT) addr, 16);
	ReleaseLock(&Lock);
	return;
}


VOID inv_range(THREADID tid, VOID *addr, int size)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] inv_range -> addr %p, size %d(0x%x)", tid, addr, size, size);
	PMC_process(invalidation, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}


VOID inv_all(THREADID tid)
{
	GetLock(&Lock, tid+1);
	//Logger.log("[tid: %d] inv_all", tid);
	PMC_process(invalidation, tid, 0, 1);
	ReleaseLock(&Lock);
	return;
}


VOID inv_master_all(THREADID tid)
{
	GetLock(&Lock, tid+1);
	PMC_process(invalidation, tid, 0, 2);
	ReleaseLock(&Lock);
	return;
}


// Writeback
VOID wb_word(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] wb_word -> addr %p", tid, addr);
	PMC_process(writeback, tid, (ADDRINT) addr, 4);
	ReleaseLock(&Lock);
	return;
}


VOID wb_dword(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] wb_dword -> addr %p", tid, addr);
	PMC_process(writeback, tid, (ADDRINT) addr, 8);
	ReleaseLock(&Lock);
	return;
}


VOID wb_qword(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] wb_qword -> addr %p", tid, addr);
	PMC_process(writeback, tid, (ADDRINT) addr, 16);
	ReleaseLock(&Lock);
	return;
}


VOID wb_range(THREADID tid, VOID *addr, int size)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] wb_range -> addr %p, size %d(0x%x)", tid, addr, size, size);
	PMC_process(writeback, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}


VOID wb_all(THREADID tid)
{
	GetLock(&Lock, tid+1);
	//Logger.log("[tid: %d] wb_all", tid);
	PMC_process(writeback, tid, 0, 1);
	ReleaseLock(&Lock);
	return;
}


VOID wb_master_all(THREADID tid)
{
	GetLock(&Lock, tid+1);
	PMC_process(writeback, tid, 0, 2);
	ReleaseLock(&Lock);
	return;
}


// Writeback-and-invalidation
VOID wb_inv_word(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_inv_word -> addr %p", tid, addr);
	PMC_process(writebackInvalidation, tid, (ADDRINT) addr, 4);
	ReleaseLock(&Lock);
	return;
}


VOID wb_inv_dword(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_inv_dword -> addr %p", tid, addr);
	PMC_process(writebackInvalidation, tid, (ADDRINT) addr, 8);
	ReleaseLock(&Lock);
	return;
}


VOID wb_inv_qword(THREADID tid, VOID *addr)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_inv_qword -> addr %p", tid, addr);
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


VOID wb_inv_all(THREADID tid)
{
	GetLock(&Lock, tid+1);
	PMC_process(writebackInvalidation, tid, 0, 1);
	ReleaseLock(&Lock);
	return;
}


VOID wb_inv_master_all(THREADID tid)
{
	GetLock(&Lock, tid+1);
	PMC_process(writebackInvalidation, tid, 0, 2);
	ReleaseLock(&Lock);
	return;
}


// Load/Store Bypass
VOID* ld_bypass(THREADID tid, VOID *addr)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] ld_bypass -> addr %p", tid, addr);
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
	Logger.debug("[tid: %d] st_bypass -> addr %p", tid, addr);
	PMC_process(storeBypass, tid, (ADDRINT) addr, 4);

	// original meaning of the instruction
	// [CAUTION] Operation on 32-bit machine is not verified.
	* ( (int *) addr) = value;
	ReleaseLock(&Lock);
	return;
}

// Load Mem
// ldmem is deprecated since its use results in non-deterministic behavior.
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
	Logger.debug("[tid: %d] wb_merge -> addr %p size %d 0x%x", tid, addr, size, size);
	PMC_process(writebackMerge, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}


// Writeback Reserve
VOID wb_reserve(THREADID tid, VOID *addr, int size)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] wb_reserve -> addr %p size %d 0x%x", tid, addr, size, size);
	PMC_process(writebackReserve, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}


// Writefirst
VOID wr_first(THREADID tid, VOID *addr, int size)
{
	GetLock(&Lock, tid+1);
	Logger.debug("[tid: %d] writefirst -> addr %p, size %d 0x%x", tid, addr, size, size);
	PMC_process(writeFirst, tid, (ADDRINT) addr, size);
	ReleaseLock(&Lock);
	return;
}


// Barrier functions
VOID* barrierInitWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* bar, VOID* some, int num)
{
	VOID *ret;

	BarrierNumber = num;
	DuringBarrierFunc[tid] = true;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret,
		PIN_PARG(VOID *), bar,
		PIN_PARG(VOID *), some,
		PIN_PARG(int), num,
		PIN_PARG_END());
	DuringBarrierFunc[tid] = false;

	return ret;
}


VOID* barrierWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* bar)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Executing barrier wrapper", tid);
	CheckBarrierResultBefore(tid);
	DuringBarrierFunc[tid] = true;
	AutoInvForEpoch[tid] = false;
	ReleaseLock(&Lock);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), bar, 
		PIN_PARG_END());
	DuringBarrierFunc[tid] = false;
	return ret;
}


VOID* threadCreateWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Creating thread wrapper", tid);
	ReleaseLock(&Lock);

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

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Joining thread wrapper", tid);
	ReleaseLock(&Lock);

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

	GetLock(&Lock, tid+1);
	//Logger.log("[tid: %d] Executing GOMP barrier wrapper", tid);
	CheckBarrierResultBefore(tid);
	ReleaseLock(&Lock);
	
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

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] OpenMP number of threads is set to %d.\n", tid, num);
	BarrierNumber = num;
	ReleaseLock(&Lock);

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

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Executing gomp_fini_work_share wrapper", tid);
	CheckBarrierResultBeforeGOMPImplicit(tid);
	Logger.log("[tid: %d] Executing gomp_fini_work_share wrapper 2", tid);
	DuringBarrierFunc[tid] = true;
	ReleaseLock(&Lock);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 	// void
		PIN_PARG(VOID *), bar, 		// struct gomp_work_share *
		PIN_PARG_END());
	DuringBarrierFunc[tid] = false;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Executing gomp_fini_work_share wrapper 3", tid);
	ReleaseLock(&Lock);

	return ret;
}


VOID* GOMP_parallel_end_Wrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Executing GOM_parallel_end wrapper", tid);
	ReleaseLock(&Lock);
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 	// void
		PIN_PARG_END());
	CheckBarrierResultBeforeGOMPImplicit(tid);

	return ret;
}


// Lock functions
VOID* lockInitWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* mutex, VOID* attr)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] LockInit 0x%lx", tid, mutex);
	MutexLocked[tid] = DuringLockFunc;
	ReleaseLock(&Lock);
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG(VOID *), attr, 
		PIN_PARG_END());

	
	LockVector.push_back((ADDRINT) mutex);
	if ((ADDRINT) mutex < MinLockVector)
		MinLockVector = (ADDRINT) mutex;
	if ((ADDRINT) mutex > MaxLockVector)
		MaxLockVector = (ADDRINT) mutex;

	MutexLocked[tid] = Unlocked;
	return ret;
}


VOID* lockWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* mutex)
{
	VOID *ret;

/*
	INT32	col, line;
	string	filename;
	col = 0; line = 0;
	filename = "";

	PIN_LockClient();
	PIN_GetSourceLocation(beforeBranch[tid], &col, &line, &filename);
	PIN_UnlockClient();
*/
	int prevLocked;
	prevLocked = MutexLocked[tid];

	GetLock(&Lock, tid+1);
	if (MutexLocked[tid] >= Locked1) {
		Logger.error("[tid: %d] nested lock (already %d times) is detected", tid, prevLocked - Unlocked);
		//Logger.error("[tid: %d] nested lock is detected at line %d, file %s", tid, line, filename.c_str());
	}
	//Logger.log("[tid: %d] Lock 0x%x", tid, mutex);
	Logger.log("[tid: %d] Lock 0x%lx, segment %d. (now, depth: %d)", tid, MutexLock[tid], SegmentCount[tid], prevLocked - Unlocked + 1);
	ReleaseLock(&Lock);

	MutexLocked[tid] = DuringLockFunc;

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG_END());

	MutexLocked[tid] = prevLocked + 1;
	MutexLock[tid][prevLocked - Unlocked] = mutex;
	// if unlocked previously, MutexLock[tid][0] will be used.
	// if locked1 previously, MutexLock[tid][1] will be used.
	// and so on

	// temp windy
	//GetLock(&Lock, tid+1);
	//Logger.log("[tid: %d] Lock 0x%x", tid, mutex);
	//ReleaseLock(&Lock);

	return ret;
}


void AnalyzeCriticalSection(int tid) 
{
	// Report if allocated memory is written but not written back.

	// source code reference for memory allocation is removed.
	//struct sourceLocation* sl;
	string s2;
	vector<struct GlobalVariableStruct>::iterator	it;
	//list<ADDRINT>::iterator	wit;
	set<ADDRINT>::iterator	wit;

	Logger.warn("[tid: %d] *** Analyzing unwritten-back writes in the critical section", tid);
	for (wit = WrittenWordsInThisLock[tid].begin(); wit != WrittenWordsInThisLock[tid].end(); wit++)
	{
		if ((*wit >= MinLockVector) && (*wit < MaxLockVector + 40)) {
			vector<ADDRINT>::iterator vit;
			BOOL found = false;
			for (vit = LockVector.begin(); vit != LockVector.end(); ++vit) 
			{
				if ((*wit >= *vit) && (*wit < *vit + 40)) {
					found = true;
					break;
				}
			}
			if (found == true)
				continue;
		}

		// check global variable
		BOOL done = false;
		for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
		{
			if ( (*wit >= (*it).addr) &&
				 (*wit < (*it).addr + (*it).size) ) {
				Logger.warn("0x%lx for %s (offset 0x%lx) is not written back.", *wit, (*it).name.c_str(), (int) (*wit - (*it).addr));
				done = true;
				break;
			}
		}
		if (done)
			continue;

		

		// temp windy
		// this code portion makes a runtime error.

		// check allocated memory
		s2 = MATracker.getVariableName(*wit);
		ADDRINT	allocAddr;
		int	allocSize;

		//Logger.log("s2=%s", s2.c_str());
		done = false;
		for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++) 
		{
			if (s2 == (*it).name) {
				allocAddr = (*it).allocAddr;
				allocSize = (*it).allocSize;
				Logger.warn("0x%lx, allocated in %s (0x%lx, offset 0x%lx, size 0x%lx), is not written back.", *wit,  s2.c_str(), allocAddr, (int) (*wit - allocAddr), allocSize);
				done = true;
				break;
			}
		}

		if (done)
			continue;
		

		struct sourceLocation *allocSrc = MATracker.getSource(*wit);
		Logger.warn("0x%lx (base 0x%lx, offset 0x%x=%d, allocated at line %d file %s) is not written back.", *wit, MATracker.getBase(*wit), MATracker.getOffset(*wit), MATracker.getOffset(*wit), allocSrc->line, allocSrc->filename.c_str());
			
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


VOID* unlockWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* mutex)
{
	VOID *ret;

	// Another checking routine is required.
	//LockBarrierResultBefore(tid);
	// temp windy
	//GetLock(&Lock, tid+1);
	int prevLocked = MutexLocked[tid];
	MutexLocked[tid] = DuringLockFunc;
	//ReleaseLock(&Lock);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG_END());

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Unlock 0x%lx, segment %d. (now, depth: %d)", tid, MutexLock[tid], SegmentCount[tid], prevLocked - Locked1);
	ReleaseLock(&Lock);

	MutexLocked[tid] = prevLocked - 1;
	MutexLock[tid][prevLocked - Locked1] = NULL;
	// if locked1 previously, MutexLock[tid][0] == NULL;
	// if locked2 previously, MutexLock[tid][1] == NULL;
	// and so on

	// instead of 
	// AutoInvForLock[tid] = false;
	if (MutexLocked[tid] == Unlocked)
		AutoInvForLock[tid] = false;

	//ReleaseLock(&Lock);

	//GetLock(&Lock, tid+1);
	// Another checking routine is required.
	//CheckBarrierResultBefore(tid);
	// temp windy
	//AnalyzeCriticalSection(tid);
	WrittenWordsInThisLock[tid].clear();
	SegmentCount[tid]++;
	//ReleaseLock(&Lock);
	return ret;
}


// Condition
VOID* condInitWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* cond, VOID* attr)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	DuringCondFunc[tid] = true;
	ReleaseLock(&Lock);
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), cond, 
		PIN_PARG(VOID *), attr, 
		PIN_PARG_END());

	GetLock(&Lock, tid+1);
	DuringCondFunc[tid] = false;
	ReleaseLock(&Lock);
	return ret;
}


VOID* condWaitWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* cond, VOID* mutex)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] before cond_wait 0x%x", tid, cond);
	ReleaseLock(&Lock);

	DuringCondFunc[tid] = true;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), cond, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG_END());

	GetLock(&Lock, tid+1);
	DuringCondFunc[tid] = false;
	Logger.log("[tid: %d] cond_wait 0x%x, segment %d", tid, cond, SegmentCount[tid]);
	SegmentCount[tid]++;
	//Ordering.whenWaitIsDone(tid, SegmentCount[tid], cond);
	ReleaseLock(&Lock);

	return ret;
}


VOID* condWaitNullWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* cond, VOID* mutex)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] before cond_wait_null 0x%x", tid, cond);
	ReleaseLock(&Lock);
	DuringCondFunc[tid] = true;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), cond, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG_END());

	GetLock(&Lock, tid+1);
	DuringCondFunc[tid] = false;
	Logger.log("[tid: %d] cond_wait_null 0x%x, segment %d", tid, cond, SegmentCount[tid]);
	SegmentCount[tid]++;
	//Ordering.whenWaitIsDone(tid, SegmentCount[tid], cond);
	ReleaseLock(&Lock);

	return ret;
}


VOID* condSignalWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* cond)
{
	VOID *ret;

	DuringCondFunc[tid] = true;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), cond, 
		PIN_PARG_END());

	GetLock(&Lock, tid+1);
	DuringCondFunc[tid] = false;
	Logger.log("[tid: %d] cond_signal 0x%x, segment %d", tid, cond, SegmentCount[tid]);
	//Ordering.whenSignal(tid, SegmentCount[tid], cond);
	SegmentCount[tid]++;
	ReleaseLock(&Lock);

	return ret;
}


VOID* condBroadcastWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* cond)
{
	VOID *ret;

	DuringCondFunc[tid] = true;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), cond, 
		PIN_PARG_END());
	
	GetLock(&Lock, tid+1);
	DuringCondFunc[tid] = false;
	Logger.log("[tid: %d] cond_broadcast 0x%x, segment %d", tid, cond, SegmentCount[tid]);
	//Ordering.whenSignal(tid, SegmentCount[tid], cond);
	SegmentCount[tid]++;
	ReleaseLock(&Lock);

	return ret;
}


//	turn on/off check functionality
//	when the check is turned off, coherence correctness is not checked.
//	this is for fast execution until interesting code section comes.
VOID turnoff_checkWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID *cond)
{
	GetLock(&Lock, tid+1);
	Logger.warn("[tid: %d] coherence check: turned off", tid);
	CheckEnabled = false;
	ReleaseLock(&Lock);
	return;
}


VOID turnon_checkWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID *cond)
{
	GetLock(&Lock, tid+1);
	Logger.warn("[tid: %d] coherence check: turned on", tid);
	CheckEnabled = true;
	ReleaseLock(&Lock);
	return;
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
	rtn = RTN_FindByName(img, "valloc_pmc");
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

	rtn = RTN_FindByName(img, "_Z10malloc_pmcj");
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

	// Mangled name is different on iacoma10 machine.
	rtn = RTN_FindByName(img, "_Z10malloc_pmcm");
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

	rtn = RTN_FindByName(img, "_Z10calloc_pmcjj");
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

	rtn = RTN_FindByName(img, "_Z10calloc_pmcmm");
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

	rtn = RTN_FindByName(img, "_Z11realloc_pmcPvj");
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

	rtn = RTN_FindByName(img, "_Z11realloc_pmcPvm");
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


	rtn = RTN_FindByName(img, "posix_memalign_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"posix_memalign_pmc", PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
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

	rtn = RTN_FindByName(img, "_Z8free_pmcPv");
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

	rtn = RTN_FindByName(img, "_Z8inv_wordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_word", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_word),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_inv_word");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_word", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_word),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z13sesc_inv_wordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_word", PIN_PARG(unsigned long), PIN_PARG_END() );
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

	rtn = RTN_FindByName(img, "_Z9inv_dwordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_dword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_dword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_inv_dword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_dword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_dword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z14sesc_inv_dwordPv");
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

 	rtn = RTN_FindByName(img, "_Z9inv_qwordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_qword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

 	rtn = RTN_FindByName(img, "sesc_inv_qword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_qword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

 	rtn = RTN_FindByName(img, "_Z17sesc_wb_inv_qwordPv");
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

	rtn = RTN_FindByName(img, "_Z9inv_rangePvi");
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

	rtn = RTN_FindByName(img, "sesc_inv_range");
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

	rtn = RTN_FindByName(img, "_Z14sesc_inv_rangePvi");
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

	rtn = RTN_FindByName(img, "inv_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z7inv_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_inv_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z12sesc_inv_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "inv_master_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z14inv_master_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_inv_master_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z19sesc_inv_master_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"inv_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(inv_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
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

	rtn = RTN_FindByName(img, "_Z7wb_wordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_word", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_word),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_wb_word");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_word", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_word),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z12sesc_wb_wordPv");
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
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_dword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z8wb_dwordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_dword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_dword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_wb_dword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_dword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_dword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z13sesc_wb_dwordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_dword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_dword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wb_qword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_qword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z8wb_qwordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_qword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_wb_qword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_qword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z13sesc_wb_qwordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_qword),
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

	rtn = RTN_FindByName(img, "_Z8wb_rangePvi");
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

	rtn = RTN_FindByName(img, "sesc_wb_range");
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

	rtn = RTN_FindByName(img, "_Z13sesc_wb_rangePvi");
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

	rtn = RTN_FindByName(img, "wb_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z6wb_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_wb_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z11sesc_wb_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wb_master_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z13wb_master_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_wb_master_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z18sesc_wb_master_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
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

	rtn = RTN_FindByName(img, "_Z11wb_inv_wordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_word", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_word),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_wb_inv_word");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_word", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_word),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}
	rtn = RTN_FindByName(img, "_Z16sesc_wb_inv_wordPv");
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

	rtn = RTN_FindByName(img, "_Z12wb_inv_dwordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_dword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_dword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_wb_inv_dword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_dword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_dword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z17sesc_wb_inv_dwordPv");
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

	rtn = RTN_FindByName(img, "_Z12wb_inv_qwordPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_qword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_wb_inv_qword");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_qword", PIN_PARG(unsigned long), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_qword),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z17sesc_wb_inv_qwordPv");
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

	rtn = RTN_FindByName(img, "_Z12wb_inv_rangePvi");
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

	rtn = RTN_FindByName(img, "sesc_wb_inv_range");
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

	rtn = RTN_FindByName(img, "_Z17sesc_wb_inv_rangePvi");
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

	rtn = RTN_FindByName(img, "wb_inv_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z10wb_inv_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_wb_inv_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z15sesc_wb_inv_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "wb_inv_master_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z17wb_inv_master_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "sesc_wb_inv_master_all");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z22sesc_wb_inv_master_allv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
			"wb_inv_master_all", PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(wb_inv_master_all),
			IARG_PROTOTYPE, proto,
			IARG_THREAD_ID,
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
		
		// pthread_mutex_init		
		rtn = RTN_FindByName(img, "pthread_mutex_init");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_mutex_init", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(lockInitWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}

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


		// pthread_cond_init
		rtn = RTN_FindByName(img, "pthread_cond_init");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_init", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condInitWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}
			
		// pthread_cond_wait
		rtn = RTN_FindByName(img, "pthread_cond_wait");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_wait", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condWaitWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}

		// pthread_cond_wait_null
		rtn = RTN_FindByName(img, "pthread_cond_wait_null");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_wait_null", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condWaitNullWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}


		// pthread_cond_wait_null
		rtn = RTN_FindByName(img, "_Z22pthread_cond_wait_nullPvS_");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_wait_null", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condWaitNullWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}

		// pthread_cond_signal
		rtn = RTN_FindByName(img, "pthread_cond_signal");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_signal", PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condSignalWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}
			
		// pthread_cond_broadcat
		rtn = RTN_FindByName(img, "pthread_cond_broadcast");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_broadcast", PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condBroadcastWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}


		rtn = RTN_FindByName(img, "turnoff_check");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"turnoff_check", PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(turnoff_checkWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_END);
		}

		rtn = RTN_FindByName(img, "turnon_check");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"turnon_check", PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(turnon_checkWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_END);
		}


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
	// Report if memory is written but not written back.

	// source code reference for memory allocation is removed.
	//struct sourceLocation* sl;
	string s2;
	vector<struct GlobalVariableStruct>::iterator	it;
	set<ADDRINT>::iterator	wit;
	gvmapit		myIt;

	Logger.warn("[tid: %d] *** Analyzing unwritten-back writes", tid);
	for (wit = WrittenWordsInThisEpoch[tid].begin(); wit != WrittenWordsInThisEpoch[tid].end(); wit++)
	{
		// check global variable		
		BOOL done = false;
		/*
		for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
		{
			if ( (*wit >= (*it).addr) &&
				 (*wit < (*it).addr + (*it).size) ) {
				Logger.warn("0x%lx for %s (offset 0x%x=%d) is not written back.", *wit, (*it).name.c_str(), (int) (*wit - (*it).addr), (int) (*wit - (*it).addr));
				done = true;
				break;
			}
		}
		if (done)
			continue;
		*/
		myIt = isGlobalVariableIterator(*wit);
		if (myIt != GlobalVariableMap.end()) {
			Logger.warn("0x%lx for %s (offset 0x%x=%d) is not written back.", *wit, (myIt->second).name.c_str(), (int) (*wit - myIt->first), (int) (*wit - myIt->first));
			continue;
		}


		// check allocated memory
		s2 = MATracker.getVariableName(*wit);
		ADDRINT	allocAddr;
		//int		allocSize;

		done = false;
		for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++) 
		{
			if (s2 == (*it).name) {
				allocAddr = (*it).allocAddr;
				//allocSize = (*it).allocSize;
				Logger.warn("0x%lx, allocated in %s (0x%lx, offset 0x%x=%d), is not written back.", *wit,  s2.c_str(), allocAddr, (int) (*wit - allocAddr), (int) (*wit - allocAddr));
				done = true;
				break;
			}
		}
		if (done)
			continue;

		struct sourceLocation *allocSrc = MATracker.getSource(*wit);
		Logger.warn("0x%lx (base 0x%lx, offset 0x%x=%d, allocated at line %d file %s) is not written back.", *wit, MATracker.getBase(*wit), MATracker.getOffset(*wit), MATracker.getOffset(*wit), allocSrc->line, allocSrc->filename.c_str());
			
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
	Logger.warn("[tid: %d] *** Analysis for writeback is done.", tid);
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
	MutexLocked[tid] = Locked1;
	Logger.log("[tid: %d] Lock", tid);
}


void unlockWrapperBefore(THREADID tid)
{
	MutexLocked[tid] = Unlocked;
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

VOID ReadsMemBefore (ADDRINT applicationIp, THREADID tid, ADDRINT memoryAddressRead, UINT32 memoryReadSize, ADDRINT sp)
{
	ADDRINT startWordAddress;
	//, endWordAddress, startOffset;
	//ADDRINT offsetMask = 0x3;

	// Before main running, we do not track read/write access.
	if (!MainRunning)
		return;

	// During pthread synchronization functions, we disable read/write tracking
	// because it will access pthread-internal data structures.
	if (DuringBarrierFunc[tid] == true)
		return;
	if (DuringCondFunc[tid] == true)
		return;
	if (MutexLocked[tid] == DuringLockFunc)
		return;

	if (CheckEnabled == false)
		return;

	if (sp != 0)
		StackPointer[tid] = sp;

	if (memoryAddressRead <= StackBase[tid] && memoryAddressRead >= StackPointer[tid])
		// read access for local stack address
		return; 

	return ;

	INT32	col, line;
	string	filename;
	col = 0; line = 0;
	filename = "";

	if (SrcWriteTracking) {
		PIN_LockClient();
		PIN_GetSourceLocation(applicationIp, &col, &line, &filename);
		PIN_UnlockClient();
	}

	//Logger.ext_debug("Global 0x6064a0 %d %d", (* (bitVectorForGlobalVariable(0x6064a0)) )[tid*2], (* (bitVectorForGlobalVariable(0x6064a0)) )[tid*2+1]);
	

	if (CheckEnabled) {
		// Now only for global/heap addresses
		addrMapIterator myIt;
		GetLock(&Lock, tid+1);
		myIt = MATracker.containIterator2(memoryAddressRead);

		if (MATracker.isAddrMapEnd(myIt) == false) {
			NumReads[tid].count++;

			startWordAddress = memoryAddressRead & ADDR_MASK;
			//endWordAddress = (memoryAddressRead + memoryReadSize) & ADDR_MASK;
			//startOffset = memoryAddressRead & offsetMask;

			for (ADDRINT a = startWordAddress; a < memoryAddressRead + memoryReadSize; a += WORD_BYTES)
			{
				// if others have dirty valid copy, 
				// this is probably problematic. 
				// Either
				// i) missing writeback from others in previous epoch
				// ii) failure to analyze OCC

				bitset<MAX_STATES>* bv;
				// bv = MATracker.bitVectorIndex(a, index);
				bv = MATracker.bitVectorIterator(a, myIt);

				for (UINT32 j = 0; j < MAX_THREADS; j++)
				{
					if (j == tid) continue;
					if ( (* bv )[j*2  ] == 1 &&
						 (* bv )[j*2+1] == 0 ) {
						// previously error, but this is not an error.
						// guess this is set as an error for checking functionality.
						Logger.error("[tid: %d] thread %d has a dirty copy, but current thread tries to read with auto invalidation for address 0x%lx, name %s, base=0x%lx, offset=0x%x at line %d file %s",
							//	tid, j, a, MATracker.getVariableNameIndex(index).c_str(), MATracker.getBaseIndex(a, index), MATracker.getOffsetIndex(a, index), line, filename.c_str());
							tid, j, a, MATracker.getVariableNameIterator(myIt).c_str(), MATracker.getBaseIterator(a, myIt), MATracker.getOffsetIterator(a, myIt), line, filename.c_str());
					}						
				}
			

				// invalidation test
				if ( (*bv )[tid*2] == 1) {
					if ( (* bv )[tid*2+1] == 1) {
						if ( ((MutexLocked[tid] >= Locked1) && AutoInvForLock[tid]) ||
							 ((MutexLocked[tid] == Unlocked) && AutoInvForEpoch[tid]) ) {
						//if (AutoInvForLock[tid] || AutoInvForEpoch[tid]) {
							// making it read valid with auto invalidation
							(* bv )[tid*2  ] = 0;
							(* bv )[tid*2+1] = 1;
							/*
							Logger.log("[tid: %d] auto invalidated for address 0x%lx, name:%s, base=0x%lx offset=0x%x", 
								//tid, a, MATracker.getVariableNameIndex(index).c_str(), MATracker.getBaseIndex(a, index), MATracker.getOffsetIndex(a, index));
								tid, a, MATracker.getVariableNameIterator(myIt).c_str(), MATracker.getBaseIterator(a, myIt), MATracker.getOffsetIterator(a, myIt));
							*/
							continue;
						}


						// means 'need invalidation'
						//GetLock(&Lock, tid+1);
						//Logger.error("[tid: %d] read without invalidation: addr=0x%lx, %s (offset %ld 0x%lx), read at line %d file %s", tid, a, MATracker.getVariableNameIndex(index).c_str(), MATracker.getOffsetIndex(a, index), MATracker.getOffsetIndex(a, index), line, filename.c_str());
						Logger.error("[tid: %d] read without invalidation: addr=0x%lx, %s (offset %ld 0x%lx), read at line %d file %s", tid, a, MATracker.getVariableNameIterator(myIt).c_str(), MATracker.getOffsetIterator(a, myIt), MATracker.getOffsetIterator(a, myIt), line, filename.c_str());
						//ReleaseLock(&Lock);
					}
					// '10' means write valid. So, no action.
				}
				else if ( (* bv )[tid*2+1] == 0) {
					// means currently invalid state, 00
					Logger.ext_debug("read at unloaded state");
					(* bv )[tid*2+1] = 1;	// changed to read valid state
				}
			}
			ReleaseLock(&Lock);
		}
		/*
		else if (isGlobalVariable(memoryAddressRead)) {
			// else if read is from global memory
			ReleaseLock(&Lock);
			NumReads[tid].count++;

			// commented out for potential overhead
			//if (MutexLocked[tid] == Locked)
			//	Logger.ext_debug("[tid: %d] epoch: %d Locked / Read address = 0x%lx", tid, BarrierCount, memoryAddressRead);
			//else
			//	Logger.ext_debug("[tid: %d] epoch: %d Read address = 0x%lx", tid, BarrierCount, memoryAddressRead);


			startWordAddress = memoryAddressRead & ADDR_MASK;
			//endWordAddress = (memoryAddressRead + memoryReadSize) & ADDR_MASK;
			//startOffset = memoryAddressRead & offsetMask;

			for (ADDRINT a = startWordAddress; a < memoryAddressRead + memoryReadSize; a += WORD_BYTES)
			{
				//	Logger.warn("[tid: %d] read : %s, %lx", tid, getGlobalVariableName(a), a);
				// if others have dirty valid copy, 
				// this is probably problematic. 
				// Either
				// i) missing writeback from others in previous epoch
				// ii) failure to analyze OCC

				for (UINT32 j = 0; j < MAX_THREADS; j++)
				{
					if (j == tid) continue;
					if ( (* (bitVectorForGlobalVariable(a)) )[j*2  ] == 1 &&
						 (* (bitVectorForGlobalVariable(a)) )[j*2+1] == 0 ) {

						// this case is a data race. 
						// this may be caused by potential miss of writeback from other cores.
						GetLock(&Lock, tid+1);
						Logger.error("[tid: %d] thread %d has dirty copy, but current thread tries to read with auto invalidation for address 0x%lx, name %s, base=0x%lx, offset=0x%x at line %d file %s",
						tid, j, a, getGlobalVariableName(a), baseInGlobalVariable(a), offsetInGlobalVariable(a), line, filename.c_str());
						ReleaseLock(&Lock);
					}						
				}

				// invalidation test
				if ( (* (bitVectorForGlobalVariable(a)) )[tid*2] == 1) {
					if ( (* (bitVectorForGlobalVariable(a)) )[tid*2+1] == 1) {

						if ( ((MutexLocked[tid] == Locked) && AutoInvForLock[tid]) ||
							 ((MutexLocked[tid] == Unlocked) && AutoInvForEpoch[tid]) ) {
							// making it read valid with auto invalidation
							(* (bitVectorForGlobalVariable(a)) )[tid*2  ] = 0;
							(* (bitVectorForGlobalVariable(a)) )[tid*2+1] = 1;
							GetLock(&Lock, tid+1);
							Logger.log("[tid: %d] auto invalidated for address 0x%lx, allocated to name:%s, base=0x%lx offset=0x%x", 
								tid, a, getGlobalVariableName(a), baseInGlobalVariable(a), offsetInGlobalVariable(a));
							ReleaseLock(&Lock);
							continue;
						}

						// means 'need invalidation'
						GetLock(&Lock, tid+1);
						Logger.error("[tid: %d] read without invalidation: addr=0x%lx, %s (offset %ld 0x%lx), read at line %d file %s", tid, a, getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a), line, filename.c_str());
						ReleaseLock(&Lock);
					}
				}
				else if ( (* (bitVectorForGlobalVariable(a)) )[tid*2+1] == 0) {
					// means currently invalid state
					Logger.ext_debug("read at unloaded state");
					(* (bitVectorForGlobalVariable(a)) )[tid*2+1] = 1;	// change to read valid state
				}
			}	// end of for loop
		}	// if global variable
		*/
		else {
			ReleaseLock(&Lock);

			gvmapit myIt = isGlobalVariableIterator(memoryAddressRead);
			if (myIt != GlobalVariableMap.end()) {
				NumReads[tid].count++;

				// commented out for potential overhead
				//if (MutexLocked[tid] == Locked)
				//	Logger.ext_debug("[tid: %d] epoch: %d Locked / Read address = 0x%lx", tid, BarrierCount, memoryAddressRead);
				//else
				//	Logger.ext_debug("[tid: %d] epoch: %d Read address = 0x%lx", tid, BarrierCount, memoryAddressRead);

				startWordAddress = memoryAddressRead & ADDR_MASK;
				//endWordAddress = (memoryAddressRead + memoryReadSize) & ADDR_MASK;
				//startOffset = memoryAddressRead & offsetMask;

				for (ADDRINT a = startWordAddress; a < memoryAddressRead + memoryReadSize; a += WORD_BYTES)
				{
					//	Logger.warn("[tid: %d] read : %s, %lx", tid, getGlobalVariableName(a), a);
					// if others have dirty valid copy, 
					// this is probably problematic. 
					// Either
					// i) missing writeback from others in previous epoch
					// ii) failure to analyze OCC

					for (UINT32 j = 0; j < MAX_THREADS; j++)
					{
						if (j == tid) continue;
						if ( (* (bitVectorForGlobalVariableIterator(a, myIt)) )[j*2  ] == 1 &&
							 (* (bitVectorForGlobalVariableIterator(a, myIt)) )[j*2+1] == 0 ) {

							// this case is a data race. 
							// this may be caused by potential miss of writeback from other cores.
							GetLock(&Lock, tid+1);
							Logger.error("[tid: %d] thread %d has a dirty copy, but current thread tries to read with auto invalidation for address 0x%lx, name %s, base=0x%lx, offset=0x%x at line %d file %s",
							tid, j, a, getGlobalVariableNameIterator(myIt), baseInGlobalVariableIterator(a, myIt), offsetInGlobalVariableIterator(a, myIt), line, filename.c_str());
							ReleaseLock(&Lock);
						}						
					}

					// invalidation test
					if ( (* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2] == 1) {
						if ( (* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] == 1) {

							if ( ((MutexLocked[tid] >= Locked1) && AutoInvForLock[tid]) ||
								 ((MutexLocked[tid] == Unlocked) && AutoInvForEpoch[tid]) ) {
								// making it read valid with auto invalidation
								(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2  ] = 0;
								(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] = 1;
								GetLock(&Lock, tid+1);
								Logger.log("[tid: %d] auto invalidated for address 0x%lx, allocated to name:%s, base=0x%lx offset=0x%x", 
									tid, a, getGlobalVariableNameIterator(myIt), baseInGlobalVariableIterator(a, myIt), offsetInGlobalVariableIterator(a, myIt));
								ReleaseLock(&Lock);
								continue;
							}

							// means 'need invalidation'
							GetLock(&Lock, tid+1);
							Logger.error("[tid: %d] read without invalidation: addr=0x%lx, %s (offset %ld 0x%lx), read at line %d file %s", 
								tid, a, getGlobalVariableNameIterator(myIt), offsetInGlobalVariableIterator(a, myIt), offsetInGlobalVariableIterator(a, myIt), line, filename.c_str());
							ReleaseLock(&Lock);
						}
					}
					else if ( (* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] == 0) {
						// means currently invalid state
						Logger.ext_debug("read at unloaded state");
						(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] = 1;	// change to read valid state
					}
				}	// end of for loop
			}	// if global variable
			else {
				// if the memory location is not within allocated area and global area,
				// we need to release the lock anyway.
				//ReleaseLock(&Lock);
			}
		}	// if else (global or others)
	}	// if (checkEnabled)	
}


VOID WritesMemBefore(ADDRINT applicationIp, THREADID tid, ADDRINT memoryAddressWrite, UINT32 memoryWriteSize, ADDRINT sp)
{
	ADDRINT startWordAddress;
	//, endWordAddress, startOffset;
	//ADDRINT offsetMask = 0x3;

	// Before main running, we do not track read/write access.
	if (!MainRunning)
		return;

	// During pthread synchronization functions, we disable read/write tracking
	// because it will access pthread-internal data structures.
	if (DuringBarrierFunc[tid] == true)
		return;
	if (DuringCondFunc[tid] == true)
		return;
	if (MutexLocked[tid] == DuringLockFunc)
		return;

	if (CheckEnabled == false) {
		// even if check is not enabled, we need to track memory allocation.
		if (AfterAlloc[tid] == false)
			return;
	}

	if (sp != 0)
		StackPointer[tid] = sp;

	if ((memoryAddressWrite <= StackBase[tid]) && (memoryAddressWrite >= StackPointer[tid]))
		// if write access for local stack address
		if (AfterAlloc[tid] == false)
			// and if not related to allocation, we are not interested in stack accesses.
			return;

	//return ;

	INT32	col, line;
	string	filename;
	col = 0; line = 0;
	filename = "";

	if (SrcWriteTracking) {
		PIN_LockClient();
		PIN_GetSourceLocation(applicationIp, &col, &line, &filename);
		PIN_UnlockClient();
	}
	//goto HERE;


	if (CheckEnabled) {
		// Now only for global/heap addresses

		// first version
		//if (MATracker.contain(memoryAddressWrite)) {
		// second version
		//if (MATracker.contain2(memoryAddressWrite)) {
		// third version
		//INT32	index;
		//index = MATracker.containIndex(memoryAddressWrite);
		//if (index >= 0) {
		// fourth version
		addrMapIterator myIt;
		GetLock(&Lock, tid+1);
		//myIt = MATracker.containIterator(memoryAddressWrite, memoryWriteSize);
		// and fifth version (current)
		// all previous versions have performance issues of O(nlogn) complexity
		// or atomicity violation.
		myIt = MATracker.containIterator2(memoryAddressWrite);
		// we need to use lock all around MATracker accesses.

		if (MATracker.isAddrMapEnd(myIt) == false) {
			// when we skip allocated area handling routine 
			//goto HERE;
			NumWrites[tid].count++;

			// the following code is just commented out to avoid any overhead.
			//if (MutexLocked[tid] == Locked)
			//	Logger.ext_debug("[tid: %d] epoch: %d Locked / Write address = 0x%lx to %s for %d",
			//		tid, BarrierCount, memoryAddressWrite, MATracker.getVariableName(memoryAddressWrite).c_str(), memoryWriteSize);
			//else
			//	Logger.ext_debug("[tid: %d] epoch: %d Write address = 0x%lx to %s for %d",
			//		tid, BarrierCount, memoryAddressWrite, MATracker.getVariableName(memoryAddressWrite).c_str(), memoryWriteSize);

			startWordAddress = memoryAddressWrite & ADDR_MASK;
			//endWordAddress = (memoryAddressWrite + memoryWriteSize) & ADDR_MASK;
			//startOffset = memoryAddressWrite & offsetMask;

			for (ADDRINT a = startWordAddress; a < memoryAddressWrite + memoryWriteSize; a += WORD_BYTES)
			{
				if (MutexLocked[tid] >= Locked1) {
					// add this word to written words group
					// the following code is for vector or list.
					// since this requires additional care for duplicated copy, we use set instead.
					//for (WrittenWordsIterator[tid] = WrittenWordsInThisLock[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisLock[tid].end(); WrittenWordsIterator[tid]++)
					//{
					//	if (*WrittenWordsIterator[tid] == a)
					//		break;
					//}
					//
					//if (WrittenWordsIterator[tid] == WrittenWordsInThisLock[tid].end())
					//	WrittenWordsInThisLock[tid].push_back(a);
					
					// stl set implementation, to avoid duplicated entry
					WrittenWordsInThisLock[tid].insert(a);
				}
				else {
					// set implementation
					WrittenWordsInThisEpoch[tid].insert(a);
				}

				// Checking if this is the latest word
				// However, for writes, this may not be required.

				/*
				if ( (* (MATracker.bitVector(a)) )[tid*2] == 1) {
					if ( (* (MATracker.bitVector(a)) )[tid*2+1] == 1) {
						// means 'need invalidation'
						//Logger.warn("[tid: %d] write without invalidation: %s (addr: 0x%lx, base 0x%lx offset %ld 0x%lx)", tid, MATracker.getVariableName(a).c_str(), a, MATracker.getBase(a), MATracker.getOffset(a), MATracker.getOffset(a));
						Logger.warn("[tid: %d] write without invalidation: addr=0x%lx, %s (offset %ld 0x%lx), read at line %d file %s", tid, a, MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a), line, filename.c_str());

					}
				}
				else if ( (* (MATracker.bitVector(a)) )[tid*2+1] == 0) {
					// means currently invalid state
					Logger.ext_debug("write at unloaded state");
					(* (MATracker.bitVector(a)) )[tid*2] = 1;
					(* (MATracker.bitVector(a)) )[tid*2+1] = 0;
				}
				else if ( (* (MATracker.bitVector(a)) )[tid*2+1] == 1) {
					// means currently read valid state
					Logger.ext_debug("write at read valid state");
					(* (MATracker.bitVector(a)) )[tid*2] = 1;
					(* (MATracker.bitVector(a)) )[tid*2+1] = 0;
				}
				*/

				//goto HERE;

			
				bitset<MAX_STATES>* bv;
				//bv = MATracker.bitVectorIndex(a, index);
				//myIt = MATracker.containIterator2(memoryAddressWrite, memoryWriteSize);
				bv = MATracker.bitVectorIterator(a, myIt);
			
				if ( (*bv)[tid*2] == 1) {
					if ((*bv)[tid*2+1] == 1) {
						// means 'need invalidation'
						//Logger.warn("[tid: %d] write without invalidation: %s (addr: 0x%lx, base 0x%lx offset %ld 0x%lx)", tid, MATracker.getVariableName(a).c_str(), a, MATracker.getBase(a), MATracker.getOffset(a), MATracker.getOffset(a));
						//Logger.warn("[tid: %d] write without invalidation: addr=0x%lx, %s (offset %ld 0x%lx), read at line %d file %s", tid, a, MATracker.getVariableName(a).c_str(), MATracker.getOffsetIndex(a, index), MATracker.getOffsetIndex(a, index), line, filename.c_str());

						//Logger.warn("[tid: %d] write without invalidation: addr=0x%lx, %s (offset %ld 0x%lx), write at line %d file %s", tid, a, MATracker.getVariableNameIterator(myIt).c_str(), MATracker.getOffsetIterator(a, myIt), MATracker.getOffsetIterator(a, myIt), line, filename.c_str());
						Logger.warn("[tid: %d] write without invalidation: addr=0x%lx, write at line %d file %s", tid, a, line, filename.c_str());

						//Logger.warn("[tid: %d] write without invalidation: addr=0x%lx, (offset %ld 0x%lx), write at line %d file %s", tid, a, MATracker.getOffsetIterator(a, myIt), MATracker.getOffsetIterator(a, myIt), line, filename.c_str());
					}
				}
				else if ( (*bv)[tid*2+1] == 0) {
					// means currently invalid state
					Logger.ext_debug("write at unloaded state");
					(* bv )[tid*2] = 1;
					(* bv )[tid*2+1] = 0;
				}
				else if ( (* bv )[tid*2+1] == 1) {
					// means currently read valid state
					Logger.ext_debug("write at read valid state");
					(* bv )[tid*2] = 1;
					(* bv )[tid*2+1] = 0;
				}			
			}

			ReleaseLock(&Lock);
		}	// end of heap-allocated memory processing
		/*
		else if (isGlobalVariable(memoryAddressWrite)) {
			// This is not dynamically changing data structure, so that we can assume no problems of thread-safety.
			// For general global memory variables, written words should be recorded.
			ReleaseLock(&Lock);
			NumWrites[tid].count++;

			// commented out for performance
			//if (MutexLocked[tid] == Locked)
			//	Logger.ext_debug("[tid: %d] epoch: %d Locked / Write address = 0x%lx to %s",
			//		tid, BarrierCount, memoryAddressWrite, getGlobalVariableName(memoryAddressWrite));
			//else
			//	Logger.ext_debug("[tid: %d] epoch:%d Write address = 0x%lx to %s",
			//		tid, BarrierCount, memoryAddressWrite, getGlobalVariableName(memoryAddressWrite));

			startWordAddress = memoryAddressWrite & ADDR_MASK;
			//endWordAddress = (memoryAddressWrite + memoryWriteSize) & ADDR_MASK;
			//startOffset = memoryAddressWrite & offsetMask;

			for (ADDRINT a = startWordAddress; a < memoryAddressWrite + memoryWriteSize; a += WORD_BYTES)
			{
				if (MutexLocked[tid] == Locked) {
				
					//for (WrittenWordsIterator[tid] = WrittenWordsInThisLock[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end(); WrittenWordsIterator[tid]++)
					//{
					//	if (*WrittenWordsIterator[tid] == a)
					//		break;
					//}
					//
					//if (WrittenWordsIterator[tid] == WrittenWordsInThisLock[tid].end())
					//	// if not added yet, add it
					//	WrittenWordsInThisLock[tid].push_back(a);
				

					// set implementation
					WrittenWordsInThisLock[tid].insert(a);
				}
				else {
		
					//for (WrittenWordsIterator[tid] = WrittenWordsInThisEpoch[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end(); WrittenWordsIterator[tid]++)
					//{
					//	if (*WrittenWordsIterator[tid] == a)
					//		break;
					//}
					//
					//if (WrittenWordsIterator[tid] == WrittenWordsInThisEpoch[tid].end())
					//	// if not added yet, add it
					//	WrittenWordsInThisEpoch[tid].push_back(a);
				

					// set implementation
					WrittenWordsInThisEpoch[tid].insert(a);

				}
	
				if ( (* (bitVectorForGlobalVariable(a)) )[tid*2] == 1) {
					if ( (* (bitVectorForGlobalVariable(a)) )[tid*2+1] == 1) {
						// means 'need invalidation'
						GetLock(&Lock, tid+1);
						Logger.warn("[tid: %d] write without invalidation: %s (offset: %ld 0x%lx)", tid, getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
						ReleaseLock(&Lock);
					}
				}
				else if ( (* (bitVectorForGlobalVariable(a)) )[tid*2+1] == 0) {
					// means currently invalid state
					Logger.ext_debug("write at unloaded state");
					(* (bitVectorForGlobalVariable(a)) )[tid*2] = 1;
					(* (bitVectorForGlobalVariable(a)) )[tid*2+1] = 0;
					//Logger.ext_debug("check2 %s", (bitVectorForGlobalVariable(0x6064a0))->to_string().c_str());
				}
				else if ( (* (bitVectorForGlobalVariable(a)) )[tid*2+1] == 1) {
					// means currently read valid state
					Logger.ext_debug("write at read valid state");
					(* (bitVectorForGlobalVariable(a)) )[tid*2] = 1;
					(* (bitVectorForGlobalVariable(a)) )[tid*2+1] = 0;
				}
			}	// end of for loop
		}	// if global variable
		*/
		else {
			ReleaseLock(&Lock);

			gvmapit myIt = isGlobalVariableIterator(memoryAddressWrite);

			if (myIt != GlobalVariableMap.end()) {
				// we have global variable match.
				// This is not dynamically changing data structure, so that we can assume no problems of thread-safety.
				// For general global memory variables, written words should be recorded.
				NumWrites[tid].count++;

				// commented out for performance
				//if (MutexLocked[tid] == Locked)
				//	Logger.ext_debug("[tid: %d] epoch: %d Locked / Write address = 0x%lx to %s",
				//		tid, BarrierCount, memoryAddressWrite, getGlobalVariableNameIterator(myIt));
				//else
				//	Logger.ext_debug("[tid: %d] epoch:%d Write address = 0x%lx to %s",
				//		tid, BarrierCount, memoryAddressWrite, getGlobalVariableNameIterator(myIt));

				startWordAddress = memoryAddressWrite & ADDR_MASK;
				//endWordAddress = (memoryAddressWrite + memoryWriteSize) & ADDR_MASK;
				//startOffset = memoryAddressWrite & offsetMask;

				for (ADDRINT a = startWordAddress; a < memoryAddressWrite + memoryWriteSize; a += WORD_BYTES)
				{
					if (MutexLocked[tid] >= Locked1) {
				
						//for (WrittenWordsIterator[tid] = WrittenWordsInThisLock[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end(); WrittenWordsIterator[tid]++)
						//{
						//	if (*WrittenWordsIterator[tid] == a)
						//		break;
						//}
						//
						//if (WrittenWordsIterator[tid] == WrittenWordsInThisLock[tid].end())
						//	// if not added yet, add it
						//	WrittenWordsInThisLock[tid].push_back(a);
				
						// set implementation
						WrittenWordsInThisLock[tid].insert(a);
					}
					else {
		
						//for (WrittenWordsIterator[tid] = WrittenWordsInThisEpoch[tid].begin(); WrittenWordsIterator[tid] != WrittenWordsInThisEpoch[tid].end(); WrittenWordsIterator[tid]++)
						//{
						//	if (*WrittenWordsIterator[tid] == a)
						//		break;
						//}
						//
						//if (WrittenWordsIterator[tid] == WrittenWordsInThisEpoch[tid].end())
						//	// if not added yet, add it
						//	WrittenWordsInThisEpoch[tid].push_back(a);

						// set implementation
						WrittenWordsInThisEpoch[tid].insert(a);
					}
	
					if ( (* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2] == 1) {
						if ( (* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] == 1) {
							// means 'need invalidation'
							GetLock(&Lock, tid+1);
							Logger.warn("[tid: %d] write without invalidation: %s (offset: %ld 0x%lx)", tid, getGlobalVariableNameIterator(myIt), offsetInGlobalVariableIterator(a, myIt), offsetInGlobalVariableIterator(a, myIt));
							ReleaseLock(&Lock);
						}
					}
					else if ( (* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] == 0) {
						// means currently invalid state
						Logger.ext_debug("write at unloaded state");
						(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2] = 1;
						(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] = 0;
						//Logger.ext_debug("check2 %s", (bitVectorForGlobalVariable(0x6064a0))->to_string().c_str());
					}
					else if ( (* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] == 1) {
						// means currently read valid state
						Logger.ext_debug("write at read valid state");
						(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2] = 1;
						(* (bitVectorForGlobalVariableIterator(a, myIt)) )[tid*2+1] = 0;
					}
				}	// end of for loop
			}	// if global variable
			else {
				// if the memory location is not within allocated area and global area,
				// lock is already released.
			}
		}	// if else (global or others)
	}	// if (CheckEnabled)

//HERE:
	if (AfterAlloc[tid]) {
		// Standard library malloc returns pointer to the variable in rax.
		// So, I guess the first write instruction with rax after malloc call has the pointer assignment.
		// This assumption is valid only when rax is used for writing to the original variable.
		// Optimization of the program might copy rax to other register, and use this new register to write to the variable.
		// Thus, we need to have unoptimized program to track allocated memory.
		// I recommend to use no optimization for the program (-O0).

		// Currently checking if this instruction is for malloc statement is ugly.
		// [TODO] Find the better way without string comparison
		GetLock(&Lock, tid+1);

		#ifdef __64BIT__
		if (strstr(DisAssemblyMap[applicationIp].c_str(), "rax")) {
		#else
		// 32-bit version should be revised according to drd version
		if (strstr(DisAssemblyMap[applicationIp].c_str(), "eax")) {
		#endif
			// Source code tracing
			INT32	col, line;
			string	filename;

			PIN_LockClient();
			PIN_GetSourceLocation(applicationIp, &col, &line, &filename);
			PIN_UnlockClient();

			Logger.log("[tid: %d] Memory allocation was done in location: col %d line %d file %s\n", tid, col, line, filename.c_str());

			MATracker.addSource(col, line, filename);

			// Global variable tracing
			//printf("[DEBUG] allocation 0x%lx\n", memoryAddressWrite);
			/*
			Logger.log("[tid: %d] memory allocation to addr 0x%lx", tid, memoryAddressWrite);
			bool done = false;
			for (GlobalVariableVecIterator = GlobalVariableVec.begin(); GlobalVariableVecIterator != GlobalVariableVec.end(); GlobalVariableVecIterator++)
			{
				if ((*GlobalVariableVecIterator).addr == memoryAddressWrite) {
					MATracker.addVariableName((*GlobalVariableVecIterator).name, 0);
					(*GlobalVariableVecIterator).allocAddr = MATracker.prevAddr;
					(*GlobalVariableVecIterator).allocSize = MATracker.prevSize;
					//(*GlobalVariableVecIterator).attachState();
					done = true;
					break;
				}
				else if ( ((*GlobalVariableVecIterator).addr < memoryAddressWrite) &&
					(memoryAddressWrite < (*GlobalVariableVecIterator).addr + (*GlobalVariableVecIterator).size) ) {
					int offset = ((*GlobalVariableVecIterator).addr + (*GlobalVariableVecIterator).size - memoryAddressWrite) / 8;
					MATracker.addVariableName((*GlobalVariableVecIterator).name, offset);
					done = true;
					break;
				}
			}
			*/
			Logger.log("[tid: %d] memory allocation to addr 0x%lx", tid, memoryAddressWrite);
			gvmapit it;
			it = isGlobalVariableIterator(memoryAddressWrite);
			if (it != GlobalVariableMap.end()) {
				if (it->first == memoryAddressWrite) {
					// startAddress 
					MATracker.addVariableName(it->second.name, 0);
					it->second.allocAddr = MATracker.prevAddr;
					it->second.allocSize = MATracker.prevSize;
					//(*GlobalVariableVecIterator).attachState();
				}
				else {
					// not a start address
					int offset = ((it->second).addr + (it->second).size - memoryAddressWrite) / WORD_BYTES;
					MATracker.addVariableName((it->second.name), offset);
				}
			}
			else {
				// if not matched to any previous global variable, this should be named as 'noname'
				MATracker.addVariableName("Noname", 0);
			}

			AfterAlloc[tid] = false;
		}
		ReleaseLock(&Lock);
	}	// if memory allocation
}	// void WritesMemBefore




//-------------------------------------------------------------------
//	Instruction Instrumentation
//-------------------------------------------------------------------

VOID Instruction(INS ins, void * v)
{
	// Finally, we will target parall worker threads only, which has threadid > 0.
	// This requires SESC to equip processor 0 with ideal memory, and instrumenting function drops its job in case of threadid 0.
	// At this moment, instrumentation targets all threads including main thread.

	// for other use of debugging
	//if (INS_IsBranch(ins) || INS_IsCall(ins) || INS_IsRet(ins)) {
	//	beforeBranch[IARG_THREAD_ID] = INS_Address(ins);
	//}

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
					IARG_REG_VALUE, REG_STACK_PTR,
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
					IARG_REG_VALUE, REG_STACK_PTR,
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

	// Stack Base address
	StackBase[tid] = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	
	if (NumThreads == 2) {
		// if first thread spawning, we need to check current writeback status.

		AnalyzeBarrierRegion(0);	// only analyze for master thread 0.
		WrittenWordsInThisEpoch[0].clear();

		Logger.warn("*** Epoch %d ended ***\n\n", BarrierCount);

		BarrierCount++;
	}

	ReleaseLock(&Lock);
}


VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 flags, VOID *V)
{
	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] *** thread is finished.\n", tid);

	NumThreads--;

	AnalyzeBarrierRegion(tid);
	WrittenWordsInThisEpoch[tid].clear();

	if (NumThreads == 1) {
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
	Logger.warn("\n\n *** Final Analysis ***\n");
	// Basic read/write info per thread
	for (int i = 0; i < MaxThreads; i++) {
		Logger.warn("tid=%d, reads=%ld, writes=%ld\n", i, NumReads[i].count, NumWrites[i].count);
	}


	// Report if allocated memory is written but not written back.

	string s2;
	vector<struct GlobalVariableStruct>::iterator	it;
	set<ADDRINT>::iterator		wit;
	BOOL	done;
	gvmapit		myIt;

	for (int i = 0; i < MaxThreads; i++) {
		Logger.log("In thread %d,\n", i);
		for (wit = WrittenWordsInThisEpoch[i].begin(); wit != WrittenWordsInThisEpoch[i].end(); wit++)
		{
			// check global variable
			/*
			for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
			{
				if ( (*wit >= (*it).addr) &&
					 (*wit < (*it).addr + (*it).size) ) {
					Logger.log("0x%lx for %s (offset 0x%x %d) is not written back.", *wit, (*it).name.c_str(), (int) (*wit - (*it).addr), (int) (*wit - (*it).addr));
					done = true;
					break;
				}
			}
			if (done)
				continue;
			*/
			myIt = isGlobalVariableIterator(*wit);
			if (myIt != GlobalVariableMap.end()) {
				Logger.warn("0x%lx for %s (offset 0x%x=%d) is not written back.", *wit, (myIt->second).name.c_str(), (int) (*wit - myIt->first), (int) (*wit - myIt->first));
				continue;
			}

			// check allocated memory
			s2 = MATracker.getVariableName(*wit);

			ADDRINT	allocAddr;
			//int		allocSize;

			done = false;
			for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++) 
			{
				if (s2 == (*it).name) {
					allocAddr = (*it).allocAddr;
					//allocSize = (*it).allocSize;
					Logger.log("0x%lx, allocated in %s (0x%lx, offset 0x%x=%d), is not written back.", *wit,  s2.c_str(), allocAddr, (int) (*wit - allocAddr), (int) (*wit - allocAddr));
					done = true;
					break;
				}
			}
			if (!done) {
				addrMapIterator ait;
				ait = MATracker.containIterator2(*wit);
				allocAddr = MATracker.getBaseIterator(*wit, ait);
				Logger.log("0x%lx, allocated in %s (0x%lx, offset 0x%x=%d), is not written back.", *wit,  s2.c_str(), allocAddr, (int) (*wit - allocAddr), (int) (*wit - allocAddr));
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
	}
}	// void FinalAnalysis


VOID Fini(INT32 code, VOID *v)
{
	// Anything required for final analysis should be written here.
	// [FIXME] final analysis is commented out temporarilly.
	FinalAnalysis();

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
		#ifdef __64BIT__
		sscanf(line, "%s %lx %x", id, &addr, &size);
		#else
		sscanf(line, "%s %x %x", id, &addr, &size);
		#endif
		if (ExcludePotentialSystemVariables) {
			if ((id[0] == '.') || (id[0] == '_'))
				continue;
			if (!strcmp("stdin", id) || !strcmp("stdout", id) || !strcmp("stderr", id))
				continue;
		}
		name = id;
		//GlobalVariableVec.push_back(GlobalVariableStruct(name, addr, size, 0, 0));
		GlobalVariableMap[addr] = GlobalVariableStruct(name, addr, size, 0, 0);
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
			else if (!strcasecmp(str, "ext")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_EXT_DEBUG);
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
			else if (!strcasecmp(str, "ext")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_EXT_DEBUG);
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

		if (!strcasecmp(str, "src_write_tracking")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "true")) {
				SrcWriteTracking = true;
			}
		}

		if (!strcasecmp(str, "src_read_tracking")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "true")) {
				SrcReadTracking = true;
			}
		}

		if (!strcasecmp(str, "check_enabled")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "false")) {
				CheckEnabled = false;
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
	SrcWriteTracking = false;
	CheckEnabled = true;

	MinLockVector = 0;
	MaxLockVector = 0;

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
		SegmentCount[i] = 0;
		AutoInvForLock[i] = false;
		AutoInvForEpoch[i] = false;
		MutexLocked[i] = Unlocked;
	}

	ReadVariableInfo(VariableFileName);
	Logger.log("*** Global Variable List starts");
	//for (GlobalVariableVecIterator = GlobalVariableVec.begin(); GlobalVariableVecIterator != GlobalVariableVec.end(); GlobalVariableVecIterator++) 
	//{
	//	Logger.log("%s: addr=0x%lx, len=0x%x", (*GlobalVariableVecIterator).name.c_str(), (*GlobalVariableVecIterator).addr, (*GlobalVariableVecIterator).size);
	//}
	for (GlobalVariableMapIterator = GlobalVariableMap.begin(); GlobalVariableMapIterator != GlobalVariableMap.end(); GlobalVariableMapIterator++) 
	{
		Logger.log("%s: addr=0x%lx, len=0x%x", (GlobalVariableMapIterator->second).name.c_str(), (GlobalVariableMapIterator->second).addr, (GlobalVariableMapIterator->second).size);
	}
	Logger.log("*** Global Variable List ends\n");

	// Instrumentation
	// At image level,
	IMG_AddInstrumentFunction(ImageLoad, 0);

	// At routine level,
	//RTN_AddInstrumentFunction(Routine, 0);

	// At instruction level,
	INS_AddInstrumentFunction(Instruction, 0);

	// Add special functions
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();		// this never returns
	return 0;
}

