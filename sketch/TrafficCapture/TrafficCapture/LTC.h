#pragma once

#include "param.h"
#include "BOBHash32.h"

class LTC {
public:	
	Cell** Buckets;
	uint8_t** Filter;
	//int d, w, m, k, M1, M2, seed;
	int d, w, m, k, seed;
	//set<uint32_t> filter;


	LTC(int _w, int _d, int _m, int _k, int _lower, int _middle, int _upper, int _period, int _seed) {
		w = _w;
		d = _d;
		m = _m;
		k = _k;
		//M1 = m * k / 8;
		//M2 = MEM * 1024 - M1;
		//w = M2 / d / 8;
		lower = _lower;
		middle = _middle;
		upper = _upper;
		step_size = _period / (float)(w * d + 0.0);
		X = Y = last_t = 0;
		seed = _seed;

		Filter = new uint8_t * [k];
		for (int i = 0; i < k; i++) {
			Filter[i] = new uint8_t[m];
			for (int j = 0; j < m; j++) {
				Filter[i][j] = 0;
			}
		}

		Buckets = new Cell * [w];
		for (int i = 0; i < w; i++) {
			Buckets[i] = new Cell[d];
			for (int j = 0; j < d; j++) {
				Buckets[i][j].flow_id = 0;
				Buckets[i][j].suspicion = Suspicion;
				Buckets[i][j].size = 0;
				Buckets[i][j].size_p = 0;
				Buckets[i][j].payload = new short[Full] {0};
			}
		}
		printf("number of buckets w: %d\n", w);
	};
	~LTC() {
		for (int i = 0; i < w; i++) {
			for (int j = 0; j < d; j++)
				delete[](Buckets[i][j].payload);
			delete[] Buckets[i];
		}
		delete[]Buckets;

		for (int i = 0; i < k; i++) 
			delete[] Filter[i];
		delete[]Filter;
	};

	uint64_t get_scanned_time() {
		return (uint64_t)step_size * (X * d + Y);
	}

	void set_last_t(uint64_t arr_time) {
		last_t = arr_time;
	}

	bool query_filter(uint32_t* flow_id) {

		int count = 0;
		
		for (int i = 0; i < k; i++) {
			bobhash = new BOBHash32(seed + i);
			uint32_t id = bobhash->run((const char*)flow_id, sizeof(uint32_t));
			count += Filter[i][id % m];
			delete bobhash;
		}
		if (count == k) return true;
		return false;
	}

	void record(Cell* cell) {
		for (int i = 0; i < k; i++) {
			bobhash = new BOBHash32(seed + i);
			uint32_t id = bobhash->run((const char*)&cell->flow_id, sizeof(uint32_t));
			Filter[i][id % m] = 1;
			delete bobhash;
		}

		if (cell->size <= 2) {
			cell->flow_id = 0;
			return;
		}

		if (cell->size >= middle && cell->size < upper) {
			cell->flow_id = 0;
			return;
		}

		int count = 0;
		for (int j = 0; j < 6; j++) {
			if (cell->payload[j] > 0)
				count++;
		}
		if (count < 4) {
			//cout << cell->flow_id << endl;
			cell->flow_id = 0;
			return;
		}

		FILE* fp = fopen(SavePath, "a");
		if (fp == 0)	
			exit(-1);
		fprintf(fp, "%u,", cell->flow_id);
		if (cell->payload[0] < 0) {
			for (int i = 0; i < Full; i++)
				cell->payload[i] = 0 - cell->payload[i];
		}

		for (int i = 0; i < Full; i++) {
			fprintf(fp, "%d", cell->payload[i]);
			if (i < Full - 1)
				fprintf(fp, ",");
			else
				fprintf(fp, "\n");
		}

		cell->flow_id = 0;
		fclose(fp);
	}

	void clean_up_sus() {
		for (int i = 0; i < w; i++) {
			for (int j = 0; j < d; j++) {
				if (Buckets[i][j].flow_id != 0 && Buckets[i][j].size_p != 0) {
					if ((Buckets[i][j].size_p >= lower && Buckets[i][j].size_p < middle) || Buckets[i][j].size_p >= upper)
						record(&Buckets[i][j]), Buckets[i][j].size_p = 0;
				}
			}
		}
	}

	int insert(uint32_t flow_id, uint64_t arr_time, short payload_size) {
		if (query_filter(&flow_id)) {
			return 1;
		}

		if (arr_time / Period == last_t / Period) { // if the item x does not cause the increment of period
			// the pointer p moves clockwise
			while (get_scanned_time() <= arr_time % Period && X != w) {
				if (Buckets[X][Y].flow_id != 0) {
					if ((Buckets[X][Y].size_p >= lower && Buckets[X][Y].size_p < middle) || Buckets[X][Y].size_p >= upper) {
						Buckets[X][Y].suspicion += 1;
						if (Buckets[X][Y].suspicion >= Threshold)
							record(&Buckets[X][Y]);
					}
					else
						Buckets[X][Y].suspicion -= 1;
					Buckets[X][Y].size_p = 0;
				}
				Y++;
				if (Y == d)
					Y = 0, X++;
				//cout << "X: " << X << " Y: " << Y << endl;
			}
			if (X == w)
				X = 0;
		}
		else { // if the item x casues the increment of period
			// similarly, the pointer p moves clockwise
			for (int i = last_t / Period; i < arr_time / Period; i++) {
				while (X != w) {
					if (Buckets[X][Y].flow_id != 0) {
						if ((Buckets[X][Y].size_p >= lower && Buckets[X][Y].size_p < middle) || Buckets[X][Y].size_p >= upper) {
							Buckets[X][Y].suspicion += 1;
							if (Buckets[X][Y].suspicion >= Threshold)
								record(&Buckets[X][Y]);
						}
						else
							Buckets[X][Y].suspicion -= 1;
						Buckets[X][Y].size_p = 0;
					}
					Y++;
					if (Y == d)
						Y = 0, X++;

					//cout << "X: " << X << " Y: " << Y << endl;
				}
				X = 0;
			}
			while (get_scanned_time() <= arr_time % Period && X != w) {
				if (Buckets[X][Y].flow_id != 0) {
					if ((Buckets[X][Y].size_p >= lower && Buckets[X][Y].size_p < middle) || Buckets[X][Y].size_p >= upper) {
						Buckets[X][Y].suspicion += 1;
						if (Buckets[X][Y].suspicion >= Threshold)
							record(&Buckets[X][Y]);
					}
					else
						Buckets[X][Y].suspicion -= 1;
					Buckets[X][Y].size_p = 0;
				}
				Y++;
				if (Y == d)
					Y = 0, X++;
				//cout << "X: " << X << " Y: " << Y << endl;
			}
			if (X == w)
				X = 0;
		}

		int index = flow_id % w;
		bool has_item = false;
		for (int i = 0; i < d; i++) {
			if (Buckets[index][i].flow_id == flow_id) {
				Buckets[index][i].payload[Buckets[index][i].size] = payload_size;
				Buckets[index][i].size += 1;
				Buckets[index][i].size_p += 1;
				if (Buckets[index][i].size_p >= middle && Buckets[index][i].size_p < upper)
					Buckets[index][i].suspicion -= 1; 
				if (Buckets[index][i].size >= Full)
					record(&Buckets[index][i]);
				has_item = true;
				break;
			}
		}
		if (!has_item) {
			int goal = -1, empty = -1, min_sus = -1, patter=-1,temp_sus = 65535;
			for (int i = 0; i < d; i++) {
				if (Buckets[index][i].flow_id == 0 && empty == -1) {
					empty = i;
					break;
				}
				else if (Buckets[index][i].size >= 6) {
					int count = 0;
					for (int j = 0; j < 6; j++) {
						if (Buckets[index][i].payload[j] > 0)
							count++;
					}
					if (count < 4) {
						patter = i; break;
					}
				}
				else if (Buckets[index][i].suspicion <= temp_sus) {
					temp_sus = Buckets[index][i].suspicion;
					min_sus = i;
				}
			}
			if (empty != -1)
				goal = empty;
			else if (patter != -1)
				goal = patter;
			else
				goal = min_sus;

			if (Buckets[index][goal].flow_id != 0)
				record(&Buckets[index][goal]);
			delete[] Buckets[index][goal].payload;
			Buckets[index][goal].flow_id = flow_id;
			Buckets[index][goal].suspicion = Suspicion;
			Buckets[index][goal].payload = new short[Full] {0};
			Buckets[index][goal].payload[0] = payload_size;
			Buckets[index][goal].size = 1;
			Buckets[index][goal].size_p = 1;
		}
		last_t = arr_time;
		return 0;
	}

private:
	int lower, middle, upper;
	int X, Y;
	float step_size;
	uint64_t last_t;
	const int ODD = 1;
	BOBHash32* bobhash = 0;
};