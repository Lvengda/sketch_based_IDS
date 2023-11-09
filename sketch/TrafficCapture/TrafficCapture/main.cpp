#include "Traffic.h"
#include "LTC.h"

//-------------------------------------------------------------------------------------
// global default settings

pcap_t* adhandle = 0;
HANDLE capture_break;
bool HANDLE_FLAG = true;
LTC ltc_online(300, 5, 10000, 4, Lower, Middle, Upper, Period, 100);

bool online = true;
//string input_pcap = "./data/synthesize_100.pcap";
string input_pcap = "./data/op_test.pcap";
string recall_file = "./data/result.txt";
string LabelPcap = "./data/label.pcap";
int Seed = 100;
map<uint32_t, uint32_t> attack_flow;
//set<uint32_t> attack_flow;

//-------------------------------------------------------------------------------------

void grid_search(const char* input, const char* output_file) {
	FILE* fp = fopen(output_file, "w");
	if (fp == NULL)
		cout << "failed to write to file: " << output_file << endl, exit(-1);
	//fprintf(fp, "Memory (KB) Seed Recall\n");
	fprintf(fp, "m,k,Precision,Recall\n");

	int m[5] = { 5000,10000,20000,30000,40000 };
	int k[5] = { 1,2,3,4,5 };

	for (int i = 0; i < 5; i++) {
		for (int j = 0; j < 5; j++) {
			run_offline(input, 1000, 4, m[i], k[j], 5, 10, 15, 1000000, Seed, fp);
		}
	}
	fclose(fp);
}

int main() {
	if (!online) {
		//grid_search(input_pcap.c_str(), "grid.txt");

		//cout << "reading label file..." << endl;
		//read_label_file();
		FILE* fp = fopen(recall_file.c_str(), "w");
		if (fp == NULL)
			cout << "failed to write to file: " << recall_file << endl, exit(-1);
		//fprintf(fp, "Memory (KB) Seed Recall\n");
		fprintf(fp, "Period,Lower,Middle,Upper,Recall\n");

		run_offline(input_pcap, 1000, 4, 30000, 4, 5, 10, 15, 1000000, Seed, fp);

		fclose(fp);
		return 0;
	}
	
	/*-----------------------------------online-----------------------------------*/
	/* set capture stop signal */
	signal(SIGINT, sig_handler);
	capture_break = (HANDLE)_beginthreadex(NULL, 0, break_handler, 0, 0, NULL);
	if (capture_break == 0) {
		printf("Failed to create new thread.\n");
		return -1;
	}
		
	/* set captured network adapter */
	cout << "select captured network adapter: " << endl;
	if ((adhandle = set_handler()) == 0) {
		printf("Failed to set handler.\n");
		return -1;
	}

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	ltc_online.clean_up_sus();

	CloseHandle(capture_break);
	//_getch();

	return 0;
}

void read_label_file() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pfile = pcap_open_offline(LabelPcap.c_str(), errbuf);
	if (pfile == NULL)
		printf("%s\n", errbuf), exit(-1);

	pcap_pkthdr* pkthdr = 0;
	const u_char* pktdata = 0;
	while (pcap_next_ex(pfile, &pkthdr, &pktdata) > 0) {
		uint32_t flow_id = get_flow_id(pktdata, Seed, NULL);
		uint32_t label=pkthdr->ts.tv_sec;
		attack_flow[flow_id] = label;
	}
	//cout << attack_flow.size() << endl; 
	pcap_close(pfile);
}

void run_offline(string input_pcap, int MEM, int d, int m, int k, int lower, int middle, int upper, int period, int seed, FILE* f_recall) {
	LTC ltc_offline = LTC(MEM, d, m, k, lower, middle, upper, period, seed + 1);

	// clean up save file
	FILE* fp = fopen(SavePath, "w");
	if (fp == NULL)
		cout << "failed to clean up file: " << SavePath << endl, exit(-1);
	fclose(fp);

	// read pcap file
	char errbuf[PCAP_ERRBUF_SIZE];	// error info buffer
	pcap_t* pfile = pcap_open_offline(input_pcap.c_str(), errbuf);
	if (pfile == NULL)
		printf("%s\n", errbuf), exit(-1);
	printf("reading %s ...\n", input_pcap.c_str());

	// insert packets into sketch
	uint32_t flow_id;
	uint64_t arr_time;
	short len;
	pcap_pkthdr* pkthdr = 0;
	const u_char* pktdata = 0;
	bool first = true;
	clock_t start_time = clock();
	while (pcap_next_ex(pfile, &pkthdr, &pktdata) > 0) {
		len = pkthdr->len;
		arr_time = (uint64_t)pkthdr->ts.tv_sec * 1000000 + pkthdr->ts.tv_usec;
		flow_id = get_flow_id(pktdata, seed, &len);

		if (first)
			ltc_offline.set_last_t(arr_time), first = false;
		ltc_offline.insert(flow_id, arr_time, len);
	}
	ltc_offline.clean_up_sus();
	
	pcap_close(pfile);

	clock_t end_time = clock();
	double run_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

	cout << run_time << endl;
	// calculate recall and precision
	if (freopen(SavePath, "r", stdin) == NULL)
		cout << "failed to read file: " << SavePath << endl, exit(-1);

	char line[MaxLineLen];
	uint32_t* suspicion_flow = new uint32_t[MaxFlowLen]{0};
	int num = 0;
	while (fgets(line, sizeof(line),stdin)) {
		char* token = strtok(line, ",");
		if (token != NULL) {
			suspicion_flow[num] = stoul(token);
			num++;
		}
	}
	fclose(stdin);

	float recall = 0;
	map<uint32_t, int>type;
	for (int i = 0; i < 6; i++) {
		type[i] = 0;
	}
	FILE* label = fopen("label.txt", "w");

	for (int i = 0; i < num; i++) {
		if (attack_flow.find(suspicion_flow[i]) != attack_flow.end()) {
			//cout << "find: " << suspicion_flow[i] << "  label: " << attack_flow[suspicion_flow[i]] << endl;
			fprintf(label, "%d,%u,%d\n", i + 1, suspicion_flow[i], attack_flow[suspicion_flow[i]]);
			if (type.find(attack_flow[suspicion_flow[i]]) != type.end())
				type[attack_flow[suspicion_flow[i]]]++;
			recall++;
		}
	}
	fclose(label);

	for (map<uint32_t, uint32_t>::iterator item = attack_flow.begin(); item != attack_flow.end(); item++) {
		int f = 0;
		for (int i = 0; i < num; i++) {
			if (item->first == suspicion_flow[i]) {
				f = 1;
				break;
			}
		}
		if (f == 0)
			cout << item->first << " label: " << item->second << endl;
	}

	for (map<uint32_t, int>::iterator item = type.begin(); item != type.end(); item++)
		cout << item->first << ": " << item->second << endl;
	delete[] suspicion_flow;

	// output results
	cout << "num: " << num << endl;
	cout << "find: " << recall << endl;
	//cout << "Memory size: " << MEM << "KB" << endl;
	cout << "Recall: " << recall / attack_flow.size() << endl;
	cout << "Precision: " << recall / num << endl;
	//fprintf(f_recall, "%d,%d,%d,%d,%f\n", period, lower, middle, upper, recall / attack_flow.size());
	fprintf(f_recall, "%d,%d,%f,%f\n", m, k, recall / num, recall / attack_flow.size());
}

uint32_t get_flow_id(const u_char* pktdata, int seed, short* payload) {
	ip_header* ih = (ip_header*)(pktdata + 14);			// point to ip header
	uint32_t ih_len = (ih->ver_ihl & 0xf) * 4;
	ip_address src = ih->saddr;
	ip_address dst = ih->daddr;
	uint16_t sp;
	uint16_t dp;

	//printf("%u.%u.%u.%u\n", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);

	if (ih->proto == 6) {
		tcp_header* th = (tcp_header*)((u_char*)ih + ih_len);	// point to tcp header 
		sp = ntohs(th->sport);
		dp = ntohs(th->dport);
	}

	else if (ih->proto == 17) {
		udp_header* uh = (udp_header*)((u_char*)ih + ih_len);	// point to tcp header 
		sp = ntohs(uh->sport);
		dp = ntohs(uh->dport);
	}

	else {
		cout << (uint16_t)ih->proto << " not tcp|ipv4 or udp|ipv4." << endl;
		return 0;
	}

	BOBHash32* bob = new BOBHash32(seed);
	
	uint32_t id1 = bob->run((const char*)&src, sizeof(src));
	uint32_t id2 = bob->run((const char*)&sp, sizeof(sp));
	uint32_t id3 = bob->run((const char*)&dst, sizeof(dst));
	uint32_t id4 = bob->run((const char*)&dp, sizeof(dp));

	delete bob;

	if (sp < dp && payload != NULL)
		*payload = 0 - *payload;
	return id1^id2^id3^id4;
}

void sig_handler(int sig) {
	if (sig == SIGINT) {
		HANDLE_FLAG = false;
	}
}

pcap_t* set_handler() {
	pcap_t* handle;
	pcap_if_t* alldevs = 0;		// list of all network adapters
	pcap_if_t* d = 0;			// selected adapter
	int inum = 0, i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];	// error info buffer
	u_int netmask = 0xffffff;

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return 0;
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return 0;
	}

	printf("Enter the interface number 1-%d(Press Ctrl+C to stop):", i);
	scanf_s("%d", &inum);

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return 0;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if (d->flags == PCAP_IF_LOOPBACK) {
		printf("%s is a loopback interface.\n", d->description);
	}

	/* Open the adapter */
	if ((handle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", errbuf);
		pcap_freealldevs(alldevs);
		return 0;
	}

	/* Set the size of the adapter kernel buffer */
	if (pcap_setbuff(handle, CAPTURE_BUFF) == -1) {
		printf("Unable to set the adapter buffer size.\n");
		pcap_freealldevs(alldevs);
		return 0;
	}

	/* Check the link layer. Support only Ethernet for simplicity. */
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return 0;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	printf("\nlistening on %s...\n", d->description);

	pcap_freealldevs(alldevs);
	return handle;
}

unsigned __stdcall break_handler(void* param) {
	while (1) {
		if (!HANDLE_FLAG) {
			printf("\nbeing stopped...\n");
			pcap_breakloop(adhandle);
			break;
		}
	}
	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	if (!HANDLE_FLAG) {
		printf("\nbeing stopped...\n");
		pcap_breakloop(adhandle);
	}

	ip_header* ih;			// point to ip header
	tcp_header* th;			// point to tcp header 
	udp_header* uh;			// point to udp header
	u_int ih_len;			// ip header's length		
	int ip_tlen;			// ip's total length	
	uint16_t sport;			// source port
	uint16_t dport;			// destination port
	uint64_t arr_time;
	uint32_t id;
	short payload;

	ih = (ip_header*)(pkt_data + 14);
	ih_len = (ih->ver_ihl & 0xf) * 4;
	ip_tlen = ntohs(ih->tlen);

	if (ih->proto == 6) {
		th = (tcp_header*)((u_char*)ih + ih_len);
		sport = ntohs(th->sport);
		dport = ntohs(th->dport);
	}
	else if (ih->proto == 17) {
		uh = (udp_header*)((u_char*)ih + ih_len);
		sport = ntohs(uh->sport);
		dport = ntohs(uh->dport);
	}

	arr_time = (uint64_t)header->ts.tv_sec * 1000000 + header->ts.tv_usec;		// to the microsecond
	payload = header->len;
	id = get_flow_id(pkt_data, Seed, &payload);
	if (id != 0) {
		cout << "insert: {" << arr_time << "," << id << "," << payload << "}" << endl;
		ltc_online.insert(id, arr_time, payload);
	}
}
