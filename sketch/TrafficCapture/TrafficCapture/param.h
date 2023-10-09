#pragma once

#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif // !_CRT_SECURE_NO_WARNINGS
#endif	

#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif // !HAVE_REMOTE

//#include <stdint.h>
#include <iostream>
#include <string>
#include <process.h>
#include <signal.h>
#include <direct.h>
#include "pcap.h"
#include <conio.h>
#include <time.h>
#include <set>
#include <map>
//#include "BOBHash32.h"
#include "xxhash32.h"

using namespace std;

#define FILTER_SIZE				40000
#define Period					1000000
#define Lower					5
#define Middle					10
#define Upper					15
#define Full					20
#define Suspicion				100
#define Threshold				101

#define SavePath				"./data/flow.csv"
#define MaxLineLen				1024
#define MaxFlowLen				65535
#define CAPTURE_BUFF			50000

struct Cell {
	uint32_t flow_id;
	uint16_t suspicion;
	uint16_t size;
	uint16_t size_p;
	short* payload;
};
