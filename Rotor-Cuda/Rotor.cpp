#include "Rotor.h"
#include "GmpUtil.h"
#include "Base58.h"
#include "sha256.cpp"
#include "hash/keccak160.h"
#include "IntGroup.h"
#include "Timer.h"
#include "hash/ripemd160.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <sstream>
#ifndef WIN64
#include <pthread.h>
#endif

using namespace std;

Point Gn[CPU_GRP_SIZE / 2];
Point _2Gn;

// ----------------------------------------------------------------------------

Rotor::Rotor(const std::string& inputFile, int compMode, int searchMode, int coinType, bool useGpu,
	const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey, int nbit2, int next, int zet, int display,
	const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
	this->compMode = compMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->inputFile = inputFile;
	this->maxFound = maxFound;
	this->rKey = rKey;
	this->nbit2 = nbit2;
	this->next = next;
	this->zet = zet;
	this->display = display;
	this->stroka = stroka;
	this->searchMode = searchMode;
	this->coinType = coinType;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeStart8.SetBase16(rangeStart.c_str());
	this->rhex.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);
	this->rangeDiffbar.Set(&this->rangeDiff2);
	this->lastrKey = 0;

	secp = new Secp256K1();
	secp->Init();

	// load file
	FILE* wfd;
	uint64_t N = 0;

	wfd = fopen(this->inputFile.c_str(), "rb");
	if (!wfd) {
		printf("  %s can not open\n", this->inputFile.c_str());
		exit(1);
	}

#ifdef WIN64
	_fseeki64(wfd, 0, SEEK_END);
	N = _ftelli64(wfd);
#else
	fseek(wfd, 0, SEEK_END);
	N = ftell(wfd);
#endif

	int K_LENGTH = 20;
	if (this->searchMode == (int)SEARCH_MODE_MX)
		K_LENGTH = 32;

	N = N / K_LENGTH;
	rewind(wfd);

	DATA = (uint8_t*)malloc(N * K_LENGTH);
	memset(DATA, 0, N * K_LENGTH);

	uint8_t* buf = (uint8_t*)malloc(K_LENGTH);;

	bloom = new Bloom(2 * N, 0.000001);

	uint64_t percent = (N - 1) / 100;
	uint64_t i = 0;
	printf("\n");
	while (i < N && !should_exit) {
		memset(buf, 0, K_LENGTH);
		memset(DATA + (i * K_LENGTH), 0, K_LENGTH);
		if (fread(buf, 1, K_LENGTH, wfd) == K_LENGTH) {
			bloom->add(buf, K_LENGTH);
			memcpy(DATA + (i * K_LENGTH), buf, K_LENGTH);
			if ((percent != 0) && i % percent == 0) {
				printf("\r  Loading      : %llu %%", (i / percent));
				fflush(stdout);
			}
		}
		i++;
	}
	fclose(wfd);
	free(buf);

	if (should_exit) {
		delete secp;
		delete bloom;
		if (DATA)
			free(DATA);
		exit(0);
	}

	BLOOM_N = bloom->get_bytes();
	TOTAL_COUNT = N;
	targetCounter = i;
	if (coinType == COIN_BTC) {
		if (searchMode == (int)SEARCH_MODE_MA)
			printf("\n  Loaded       : %s Bitcoin addresses\n", formatThousands(i).c_str());
		else if (searchMode == (int)SEARCH_MODE_MX)
			printf("\n  Loaded       : %s Bitcoin xpoints\n", formatThousands(i).c_str());
	}
	else {
		printf("\n  Loaded       : %s Ethereum addresses\n", formatThousands(i).c_str());
	}

	printf("\n");

	bloom->print();
	printf("\n");

	InitGenratorTable();

}

// ----------------------------------------------------------------------------

Rotor::Rotor(const std::vector<unsigned char>& hashORxpoint, int compMode, int searchMode, int coinType,
	bool useGpu, const std::string& outputFile, bool useSSE, uint32_t maxFound, uint64_t rKey, int nbit2, int next, int zet, int display,
	const std::string& rangeStart, const std::string& rangeEnd, bool& should_exit)
{
	this->compMode = compMode;
	this->useGpu = useGpu;
	this->outputFile = outputFile;
	this->useSSE = useSSE;
	this->nbGPUThread = 0;
	this->maxFound = maxFound;
	this->rKey = rKey;
	this->next = next;
	this->zet = zet;
	this->display = display;
	this->stroka = stroka;
	this->searchMode = searchMode;
	this->coinType = coinType;
	this->rangeStart.SetBase16(rangeStart.c_str());
	this->rangeStart8.SetBase16(rangeStart.c_str());
	this->rhex.SetBase16(rangeStart.c_str());
	this->rangeEnd.SetBase16(rangeEnd.c_str());
	this->rangeDiff2.Set(&this->rangeEnd);
	this->rangeDiff2.Sub(&this->rangeStart);
	this->rangeDiffcp.Set(&this->rangeDiff2);
	this->rangeDiffbar.Set(&this->rangeDiff2);
	this->targetCounter = 1;
	this->nbit2 = nbit2;
	secp = new Secp256K1();
	secp->Init();

	if (this->searchMode == (int)SEARCH_MODE_SA) {
		assert(hashORxpoint.size() == 20);
		for (size_t i = 0; i < hashORxpoint.size(); i++) {
			((uint8_t*)hash160Keccak)[i] = hashORxpoint.at(i);
		}
	}
	else if (this->searchMode == (int)SEARCH_MODE_SX) {
		assert(hashORxpoint.size() == 32);
		for (size_t i = 0; i < hashORxpoint.size(); i++) {
			((uint8_t*)xpoint)[i] = hashORxpoint.at(i);
		}
	}
	printf("\n");

	InitGenratorTable();
}

// ----------------------------------------------------------------------------

void Rotor::InitGenratorTable()
{
	// Compute Generator table G[n] = (n+1)*G
	Point g = secp->G;
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for (int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g, secp->G);
		Gn[i] = g;
	}
	// _2Gn = CPU_GRP_SIZE*G
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);

	char* ctimeBuff;
	time_t now = time(NULL);
	ctimeBuff = ctime(&now);
	printf("  Start Time   : %s", ctimeBuff);

	if (rKey < 1) {

		if (next > 0) {
			ifstream file777("Rotor-Cuda_Continue.bat");
			string s777;
			string kogda;

			for (int i = 0; i < 5; i++) {
				getline(file777, s777);

				if (i == 1) {
					stroka = s777;
				}
				if (i == 3) {
					string kogda = s777;
					if (kogda != "") {
						printf("  Rotor        : Continuing search from BAT file. Checkpoint %s \n\n", kogda.c_str());
					}
				}
				if (i == 4) {
					string streek = s777;
					std::istringstream iss(streek);
					iss >> value777;
					uint64_t dobb = value777 / 1;
					rhex.Add(dobb);
				}
			}

			if (kogda == "") {
				ifstream file778("Rotor-Cuda_START.bat");
				string s778;
				string kogda;
				stroka = "";
				for (int i = 0; i < 3; i++) {
					getline(file778, s778);

					if (i == 1) {
						stroka = s778;
					}
				}
			}
		}
	}
	if (display == 0) {

		if (rKey == 0) {
			
			if (nbit2 > 0) {
				Int tThreads77;
				tThreads77.SetInt32(nbit2);
				rangeDiffcp.Div(&tThreads77);

				gir.Set(&rangeDiff2);
				Int reh;
				uint64_t nextt99;
				nextt99 = value777 * 1;
				reh.Add(nextt99);
				gir.Sub(&reh);
				if (value777 > 1) {
					printf("\n  Rotor info   : Continuation... Divide the remaining range %s (%d bit) into CPU %d cores \n", gir.GetBase16().c_str(), gir.GetBitLength(), nbit2);
				}
			}
		}
	}
	else {

		if (rKey == 0) {
			printf("  Global start : %s (%d bit)\n", this->rangeStart.GetBase16().c_str(), this->rangeStart.GetBitLength());
			printf("  Global end   : %s (%d bit)\n", this->rangeEnd.GetBase16().c_str(), this->rangeEnd.GetBitLength());
			printf("  Global range : %s (%d bit)\n", this->rangeDiff2.GetBase16().c_str(), this->rangeDiff2.GetBitLength());

			if (nbit2 > 0) {
				Int tThreads77;
				tThreads77.SetInt32(nbit2);
				rangeDiffcp.Div(&tThreads77);

				gir.Set(&rangeDiff2);
				Int reh;
				uint64_t nextt99;
				nextt99 = value777 * 1;
				reh.Add(nextt99);
				gir.Sub(&reh);
				if (value777 > 1) {
					printf("\n  Rotor info   : Continuation... Divide the remaining range %s (%d bit) into CPU %d cores \n", gir.GetBase16().c_str(), gir.GetBitLength(), nbit2);
				}
				else {
					printf("\n  Rotor info   : Divide the range %s (%d bit) into CPU %d cores for fast parallel search \n", rangeDiff2.GetBase16().c_str(), rangeDiff2.GetBitLength(), nbit2);
				}
			}
		}
	
	}
	
}

// ----------------------------------------------------------------------------

Rotor::~Rotor()
{
	delete secp;
	if (searchMode == (int)SEARCH_MODE_MA || searchMode == (int)SEARCH_MODE_MX)
		delete bloom;
	if (DATA)
		free(DATA);
}

// ----------------------------------------------------------------------------

double log1(double x)
{
	// Use taylor series to approximate log(1-x)
	return -x - (x * x) / 2.0 - (x * x * x) / 3.0 - (x * x * x * x) / 4.0;
}

void Rotor::output(std::string addr, std::string pAddr, std::string pAddrHex, std::string pubKey)
{

#ifdef WIN64
	WaitForSingleObject(ghMutex, INFINITE);
#else
	pthread_mutex_lock(&ghMutex);
#endif

	FILE* f = stdout;
	bool needToClose = false;

	if (outputFile.length() > 0) {
		f = fopen(outputFile.c_str(), "a");
		if (f == NULL) {
			printf("  Cannot open %s for writing\n", outputFile.c_str());
			f = stdout;
		}
		else {
			needToClose = true;
		}
	}

	if (!needToClose)
		printf("\n");
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	fprintf(f, "PubAddress: %s\n", addr.c_str());
	fprintf(stdout, "\n  =================================================================================\n");
	fprintf(stdout, "  PubAddress: %s\n", addr.c_str());

	if (coinType == COIN_BTC) {
		fprintf(f, "Priv (WIF): p2pkh:%s\n", pAddr.c_str());
		fprintf(stdout, "  Priv (WIF): p2pkh:%s\n", pAddr.c_str());
	}

	fprintf(f, "Priv (HEX): %s\n", pAddrHex.c_str());
	fprintf(stdout, "  Priv (HEX): %s\n", pAddrHex.c_str());

	fprintf(f, "PubK (HEX): %s\n", pubKey.c_str());
	fprintf(stdout, "  PubK (HEX): %s\n", pubKey.c_str());

	fprintf(f, "=================================================================================\n");
	fprintf(stdout, "  =================================================================================\n");

	if (needToClose)
		fclose(f);

#ifdef WIN64
	ReleaseMutex(ghMutex);
#else
	pthread_mutex_unlock(&ghMutex);
#endif

}

// ----------------------------------------------------------------------------

bool Rotor::checkPrivKey(std::string addr, Int& key, int32_t incr, bool mode)
{
	Int k(&key), k2(&key);
	k.Add((uint64_t)incr);
	k2.Add((uint64_t)incr);
	// Check addresses
	Point p = secp->ComputePublicKey(&k);
	std::string px = p.x.GetBase16();
	std::string chkAddr = secp->GetAddress(mode, p);
	if (chkAddr != addr) {
		//Key may be the opposite one (negative zero or compressed key)
		k.Neg();
		k.Add(&secp->order);
		p = secp->ComputePublicKey(&k);
		std::string chkAddr = secp->GetAddress(mode, p);
		if (chkAddr != addr) {
			printf("\n=================================================================================\n");
			printf("  Warning, wrong private key generated !\n");
			printf("  PivK : %s\n", k2.GetBase16().c_str());
			printf("  Addr : %s\n", addr.c_str());
			printf("  PubX : %s\n", px.c_str());
			printf("  PivK : %s\n", k.GetBase16().c_str());
			printf("  Check: %s\n", chkAddr.c_str());
			printf("  PubX : %s\n", p.x.GetBase16().c_str());
			printf("=================================================================================\n");
			return false;
		}
	}
	output(addr, secp->GetPrivAddress(mode, k), k.GetBase16(), secp->GetPublicKeyHex(mode, p));
	return true;
}

bool Rotor::checkPrivKeyETH(std::string addr, Int& key, int32_t incr)
{
	Int k(&key), k2(&key);
	k.Add((uint64_t)incr);
	k2.Add((uint64_t)incr);
	// Check addresses
	Point p = secp->ComputePublicKey(&k);
	std::string px = p.x.GetBase16();
	std::string chkAddr = secp->GetAddressETH(p);
	if (chkAddr != addr) {
		//Key may be the opposite one (negative zero or compressed key)
		k.Neg();
		k.Add(&secp->order);
		p = secp->ComputePublicKey(&k);
		std::string chkAddr = secp->GetAddressETH(p);
		if (chkAddr != addr) {
			printf("\n=================================================================================\n");
			printf("  Warning, wrong private key generated !\n");
			printf("  PivK :%s\n", k2.GetBase16().c_str());
			printf("  Addr :%s\n", addr.c_str());
			printf("  PubX :%s\n", px.c_str());
			printf("  PivK :%s\n", k.GetBase16().c_str());
			printf("  Check:%s\n", chkAddr.c_str());
			printf("  PubX :%s\n", p.x.GetBase16().c_str());
			printf("=================================================================================\n");
			return false;
		}
	}
	output(addr, k.GetBase16()/*secp->GetPrivAddressETH(k)*/, k.GetBase16(), secp->GetPublicKeyHexETH(p));
	return true;
}

bool Rotor::checkPrivKeyX(Int& key, int32_t incr, bool mode)
{
	Int k(&key);
	k.Add((uint64_t)incr);
	Point p = secp->ComputePublicKey(&k);
	std::string addr = secp->GetAddress(mode, p);
	output(addr, secp->GetPrivAddress(mode, k), k.GetBase16(), secp->GetPublicKeyHex(mode, p));
	return true;
}

// ----------------------------------------------------------------------------

#ifdef WIN64
DWORD WINAPI _FindKeyCPU(LPVOID lpParam)
{
#else
void* _FindKeyCPU(void* lpParam)
{
#endif
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyCPU(p);
	return 0;
}

#ifdef WIN64
DWORD WINAPI _FindKeyGPU(LPVOID lpParam)
{
#else
void* _FindKeyGPU(void* lpParam)
{
#endif
	TH_PARAM* p = (TH_PARAM*)lpParam;
	p->obj->FindKeyGPU(p);
	return 0;
}

// ----------------------------------------------------------------------------

void Rotor::checkMultiAddresses(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHash160(compressed, p1, h0);
	if (CheckBloomBinary(h0, 20) > 0) {
		std::string addr = secp->GetAddress(compressed, h0);
		if (checkPrivKey(addr, key, i, compressed)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Rotor::checkMultiAddressesETH(Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHashETH(p1, h0);
	if (CheckBloomBinary(h0, 20) > 0) {
		std::string addr = secp->GetAddressETH(h0);
		if (checkPrivKeyETH(addr, key, i)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Rotor::checkSingleAddress(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHash160(compressed, p1, h0);
	if (MatchHash((uint32_t*)h0)) {
		std::string addr = secp->GetAddress(compressed, h0);
		if (checkPrivKey(addr, key, i, compressed)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Rotor::checkSingleAddressETH(Int key, int i, Point p1)
{
	unsigned char h0[20];

	// Point
	secp->GetHashETH(p1, h0);
	if (MatchHash((uint32_t*)h0)) {
		std::string addr = secp->GetAddressETH(h0);
		if (checkPrivKeyETH(addr, key, i)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Rotor::checkMultiXPoints(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[32];

	// Point
	secp->GetXBytes(compressed, p1, h0);
	if (CheckBloomBinary(h0, 32) > 0) {
		if (checkPrivKeyX(key, i, compressed)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Rotor::checkSingleXPoint(bool compressed, Int key, int i, Point p1)
{
	unsigned char h0[32];

	// Point
	secp->GetXBytes(compressed, p1, h0);
	if (MatchXPoint((uint32_t*)h0)) {
		if (checkPrivKeyX(key, i, compressed)) {
			nbFoundKey++;
		}
	}
}

// ----------------------------------------------------------------------------

void Rotor::checkMultiAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4)
{
	unsigned char h0[20];
	unsigned char h1[20];
	unsigned char h2[20];
	unsigned char h3[20];

	// Point -------------------------------------------------------------------------
	secp->GetHash160(compressed, p1, p2, p3, p4, h0, h1, h2, h3);
	if (CheckBloomBinary(h0, 20) > 0) {
		std::string addr = secp->GetAddress(compressed, h0);
		if (checkPrivKey(addr, key, i + 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h1, 20) > 0) {
		std::string addr = secp->GetAddress(compressed, h1);
		if (checkPrivKey(addr, key, i + 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h2, 20) > 0) {
		std::string addr = secp->GetAddress(compressed, h2);
		if (checkPrivKey(addr, key, i + 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (CheckBloomBinary(h3, 20) > 0) {
		std::string addr = secp->GetAddress(compressed, h3);
		if (checkPrivKey(addr, key, i + 3, compressed)) {
			nbFoundKey++;
		}
	}

}

// ----------------------------------------------------------------------------

void Rotor::checkSingleAddressesSSE(bool compressed, Int key, int i, Point p1, Point p2, Point p3, Point p4)
{
	unsigned char h0[20];
	unsigned char h1[20];
	unsigned char h2[20];
	unsigned char h3[20];

	// Point -------------------------------------------------------------------------
	secp->GetHash160(compressed, p1, p2, p3, p4, h0, h1, h2, h3);
	if (MatchHash((uint32_t*)h0)) {
		std::string addr = secp->GetAddress(compressed, h0);
		if (checkPrivKey(addr, key, i + 0, compressed)) {
			nbFoundKey++;
		}
	}
	if (MatchHash((uint32_t*)h1)) {
		std::string addr = secp->GetAddress(compressed, h1);
		if (checkPrivKey(addr, key, i + 1, compressed)) {
			nbFoundKey++;
		}
	}
	if (MatchHash((uint32_t*)h2)) {
		std::string addr = secp->GetAddress(compressed, h2);
		if (checkPrivKey(addr, key, i + 2, compressed)) {
			nbFoundKey++;
		}
	}
	if (MatchHash((uint32_t*)h3)) {
		std::string addr = secp->GetAddress(compressed, h3);
		if (checkPrivKey(addr, key, i + 3, compressed)) {
			nbFoundKey++;
		}
	}

}

// ----------------------------------------------------------------------------

void Rotor::getCPUStartingKey(Int & tRangeStart, Int & tRangeEnd, Int & key, Point & startP)
{
	if (rKey <= 0) {

		uint64_t nextt = 0;
		if (value777 > 1) {
			nextt = value777 / nbit2;
			tRangeStart.Add(nextt);
		}
		key.Set(&tRangeStart);
		Int kon;
		kon.Set(&tRangeStart);
		kon.Add(&rangeDiffcp);
		trk = trk + 1;
		if (display > 0) {

			if (trk == nbit2) {
				printf("  CPU Core (%d) : %s -> %s \n\n", trk, key.GetBase16().c_str(), rangeEnd.GetBase16().c_str());
			}
			else {
				printf("  CPU Core (%d) : %s -> %s \n", trk, key.GetBase16().c_str(), kon.GetBase16().c_str());
			}
		
		}
		Int km(&key);
		km.Add((uint64_t)CPU_GRP_SIZE / 2);
		startP = secp->ComputePublicKey(&km);
	}
	else {
		
		if (rangeDiff2.GetBitLength() > 10) {
			
			key.Set(&rangeStart8);
			int fgg = rangeDiff2.GetBitLength();
			int nk = rand() % fgg;
			Int ddv;
			
			int sak = 1 + rand() % 3;

			if (sak == 1) {
				ddv.Rand(&rangeDiff2);
				key.Add(&ddv);
				rhex = key;
			}
			if (sak == 2) {
				ddv.Rand(&rangeDiff2);
				key.Add(&ddv);
				rhex = key;
			}

			if (sak == 3) {

				int stt = 1 + rand() % 100;

				if (stt < 90) {
					int fgg = rangeDiff2.GetBitLength();
					ddv.Rand(fgg);
					key.Add(&ddv);
					rhex = key;

				}
				else {

					int fgg = rangeDiff2.GetBitLength();
					int sakr = 1 + rand() % fgg;
					ddv.Rand(sakr);
					key.Add(&ddv);
					rhex = key;
				}
			}
			
			Int km(&key);
			km.Add((uint64_t)CPU_GRP_SIZE / 2);
			startP = secp->ComputePublicKey(&km);
			
		}
		else {

			if (next > 256) {
				printf("\n  ROTOR Random : Are you serious %d bit ??? \n", next);
				exit(1);
			}
			if (zet > 256) {
				printf("\n  ROTOR Random : Are you serious -z %d bit ??? \n", zet);
				exit(1);
			}

			if (next == 0) {
				key.Rand(256);
				rhex = key;
				Int km(&key);
				km.Add((uint64_t)CPU_GRP_SIZE / 2);
				startP = secp->ComputePublicKey(&km);
			}
			else {

				int next2 = 0;
				int dfs = zet - next;

				if (zet > 1) {

					if (zet <= next) {
						printf("\n  ROTOR Random : Are you serious -n %d (start) -z %d (end) ??? \n  The start must be less than the end \n", next, zet);
						exit(1);
					}

					if (dfs == 1) {
						next2 = next + rand() % 2;
					}
					else {

						next2 = next + rand() % dfs;
						next2 = next2 + rand() % 2;
					}
				}
				else {

					next2 = next;
				}

				if (next2 == 1) {

					int N = 20 + rand() % 45;

					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 2) {
					int N = 30 + rand() % 35;

					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 3) {
					int N = 40 + rand() % 25;

					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 4) {
					int N = 50 + rand() % 15;

					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 5) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 1;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 6) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 1;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 7) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 1;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 8) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 1;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 9) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 2;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 10) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 2;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 11) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 2;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 12) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 2;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 13) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 3;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 14) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 3;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 15) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 3;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 16) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 3;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 17) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 4;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 18) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 4;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 19) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 4;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 20) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 4;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 21) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 5;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 22) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 5;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 23) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 5;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 24) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 5;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 25) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 6;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 26) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 6;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 27) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 6;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 28) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 6;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 29) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 7;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 30) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 7;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 31) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 7;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 32) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 7;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 33) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 8;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 34) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 8;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 35) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 8;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 36) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 8;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 37) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 9;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 38) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 9;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 39) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 9;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 40) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 9;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 41) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 10;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 42) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 10;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 43) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 10;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 44) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 10;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 45) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 11;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 46) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 11;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 47) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 11;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 48) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 11;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 49) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 12;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 50) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 12;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 51) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 12;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 52) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 12;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 53) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 13;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 54) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 13;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 55) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 13;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 56) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 13;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 57) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 14;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 58) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 14;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 59) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 14;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 60) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 14;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 61) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 15;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 62) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 15;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 63) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 15;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 64) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 15;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 65) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 16;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 66) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 16;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 67) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 16;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 68) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 16;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 69) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 17;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 70) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 17;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 71) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 17;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 72) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 17;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 73) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 18;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 74) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 18;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 75) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 18;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 76) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 18;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 77) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 19;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 78) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 19;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 79) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 19;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 80) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 19;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 81) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 20;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 82) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 20;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 83) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 20;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 84) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 20;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 85) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 21;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 86) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 21;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 87) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 21;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 88) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 21;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 89) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 22;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 90) {
					int N2 = 4;
					char str2[]{ "4567" };
					int strN2 = 1;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 22;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 91) {
					int N2 = 4;
					char str2[]{ "89ab" };
					int strN2 = 1;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 22;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 92) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 22;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 93) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 23;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 94) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 23;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 95) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 23;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 96) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 23;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 97) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 24;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 98) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 24;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 99) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 24;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 100) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 24;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 101) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 25;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 102) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 25;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 103) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 25;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 104) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 25;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 105) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 26;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 106) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 26;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 107) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 26;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 108) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 26;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 109) {
					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 27;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 110) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 27;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 111) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 27;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 112) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 27;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 113) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 28;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 114) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 28;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 115) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 28;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 116) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 28;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 117) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 29;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 118) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 29;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 119) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 29;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 120) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 29;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 121) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 30;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 122) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 30;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 123) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 30;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 124) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 30;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 125) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 31;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 126) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 31;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 127) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 31;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 128) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 31;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 129) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 32;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 130) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 32;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 131) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 32;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 132) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 32;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 133) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 33;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 134) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 33;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 135) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 33;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 136) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 33;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 137) {
					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 34;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 138) {
					int N2 = 4;
					char str2[]{ "4567" };
					int strN2 = 1;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 34;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 139) {

					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 34;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 140) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 34;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 141) {
					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 35;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 142) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 35;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 143) {

					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 35;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 144) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 35;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 145) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 36;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 146) {

					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 36;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 147) {

					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 36;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 148) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 36;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 149) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 37;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 150) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 37;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 151) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 37;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 152) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 37;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 153) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 38;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 154) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 38;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 155) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 38;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 156) {
					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 38;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 157) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 39;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 158) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 39;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 159) {

					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 39;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 160) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 39;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 161) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 40;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 162) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 40;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 163) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 40;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 164) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 40;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 165) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 41;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 166) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 41;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 167) {

					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 41;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 168) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 41;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 169) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 42;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 170) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 42;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 171) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 42;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 172) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 42;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 173) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 43;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 174) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 43;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 175) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 43;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 176) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 43;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 177) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 44;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 178) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 44;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 179) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 44;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 180) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 44;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 181) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 45;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 182) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 45;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 183) {

					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 45;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 184) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 45;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 185) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 46;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 186) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 46;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 187) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 46;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 188) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 46;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 189) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 47;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 190) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 47;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 191) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 47;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 192) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 47;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 193) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 48;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 194) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 48;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 195) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 48;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 196) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 48;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 197) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 49;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 198) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 49;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 199) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 49;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 200) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 49;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 201) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 50;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 202) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 50;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 203) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 50;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 204) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 50;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 205) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 51;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 206) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 51;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 207) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 51;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 208) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 51;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 209) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 52;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 210) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 52;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 211) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 52;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 212) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 52;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 213) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 53;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 214) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 53;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 215) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 53;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 216) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 53;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 217) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 54;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 218) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 54;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 219) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 54;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 220) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 54;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 221) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 55;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 222) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 55;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 223) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 55;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 224) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 55;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 225) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 56;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 226) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 56;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 227) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 56;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 228) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 56;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 229) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 57;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 230) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 57;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 231) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 57;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 232) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 57;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 233) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 58;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 234) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 58;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 235) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 58;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 236) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 58;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 237) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 59;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 238) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 59;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 239) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 59;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 240) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 59;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}

				if (next2 == 241) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 60;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 242) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 60;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 243) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 60;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 244) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 60;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 245) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 61;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 246) {

					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 61;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 247) {

					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 61;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 248) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 61;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 249) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 62;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 250) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 62;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 251) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 62;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);


				}
				if (next2 == 252) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 62;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 253) {

					int N2 = 1;
					char str2[]{ "123" };
					int strN2 = 3;

					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 63;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 254) {
					int N2 = 1;
					char str2[]{ "4567" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 63;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}
				if (next2 == 255) {
					int N2 = 1;
					char str2[]{ "89ab" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 63;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);

				}
				if (next2 == 256) {

					int N2 = 1;
					char str2[]{ "cdef" };
					int strN2 = 4;
					char* pass2 = new char[N2 + 1];
					for (int i = 0; i < N2; i++)
					{
						pass2[i] = str2[rand() % strN2];
					}
					pass2[N2] = 0;

					int N = 63;
					char str[]{ "0123456789abcdef" };
					int strN = 16;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;
					std::stringstream ss;
					ss << pass2 << pass;
					std::string input = ss.str();
					char* cstr = &input[0];
					key.SetBase16(cstr);
					rhex.SetBase16(cstr);
				}

				Int km(&key);
				km.Add((uint64_t)CPU_GRP_SIZE / 2);
				startP = secp->ComputePublicKey(&km);
			}
		
		}
	}
}

void Rotor::FindKeyCPU(TH_PARAM * ph)
{
	
	// Global init
	int thId = ph->threadId;
	
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;
	counters[thId] = 0;
	if (rKey < 1) {

		if (thId == 0) {
			
			if (display > 0) {
				
				if (next > 0) {
					printf("  Rotor info   : Save checkpoints every %d minutes. For continue range, run the bat file Rotor-Cuda_Continue.bat \n", next);
				}

			}
		}
	}
	
	if (rKey > 0) {

		if (rKeyCount2 == 0) {
			
			if (thId == 0) {

				if (rangeDiff2.GetBitLength() < 1) {

					if (next == 0) {

						if (display > 0) {
							printf("  Rotor Random : Generate Private keys in Ranges 95%% (252-256) bit + 5%% (248-252) bit \n");
						}
					}
					else {

						if (zet > 1) {
							string konn;

							if (zet == 5) {
								konn = "3F";
							}
							if (zet == 6) {
								konn = "7F";
							}
							if (zet == 7) {
								konn = "BF";
							}
							if (zet == 8) {
								konn = "FF";
							}
							if (zet == 9) {
								konn = "3FF";
							}
							if (zet == 10) {
								konn = "7FF";
							}
							if (zet == 11) {
								konn = "BFF";
							}
							if (zet == 12) {
								konn = "FFF";
							}
							if (zet == 13) {
								konn = "3FFF";
							}
							if (zet == 14) {
								konn = "7FFF";
							}
							if (zet == 15) {
								konn = "BFFF";
							}
							if (zet == 16) {
								konn = "FFFF";
							}
							if (zet == 17) {
								konn = "3FFFF";
							}
							if (zet == 18) {
								konn = "7FFFF";
							}
							if (zet == 19) {
								konn = "BFFFF";
							}
							if (zet == 20) {
								konn = "FFFFF";
							}
							if (zet == 21) {
								konn = "3FFFFF";
							}
							if (zet == 22) {
								konn = "7FFFFF";
							}
							if (zet == 23) {
								konn = "BFFFFF";
							}
							if (zet == 24) {
								konn = "FFFFFF";
							}
							if (zet == 25) {
								konn = "3FFFFFF";
							}
							if (zet == 26) {
								konn = "7FFFFFF";
							}
							if (zet == 27) {
								konn = "BFFFFFF";
							}
							if (zet == 28) {
								konn = "FFFFFFF";
							}
							if (zet == 29) {
								konn = "3FFFFFFF";
							}
							if (zet == 30) {
								konn = "7FFFFFFF";
							}
							if (zet == 31) {
								konn = "BFFFFFFF";
							}
							if (zet == 32) {
								konn = "FFFFFFFF";
							}
							if (zet == 33) {
								konn = "3FFFFFFFF";
							}
							if (zet == 34) {
								konn = "7FFFFFFFF";
							}
							if (zet == 35) {
								konn = "BFFFFFFFF";
							}
							if (zet == 36) {
								konn = "FFFFFFFFF";
							}
							if (zet == 37) {
								konn = "3FFFFFFFFF";
							}
							if (zet == 38) {
								konn = "7FFFFFFFFF";
							}
							if (zet == 39) {
								konn = "BFFFFFFFFF";
							}
							if (zet == 40) {
								konn = "FFFFFFFFFF";
							}
							if (zet == 41) {
								konn = "3FFFFFFFFFF";
							}
							if (zet == 42) {
								konn = "7FFFFFFFFFF";
							}
							if (zet == 43) {
								konn = "BFFFFFFFFFF";
							}
							if (zet == 44) {
								konn = "FFFFFFFFFFF";
							}
							if (zet == 45) {
								konn = "3FFFFFFFFFFF";
							}
							if (zet == 46) {
								konn = "7FFFFFFFFFFF";
							}
							if (zet == 47) {
								konn = "BFFFFFFFFFFF";
							}
							if (zet == 48) {
								konn = "FFFFFFFFFFFF";
							}
							if (zet == 49) {
								konn = "3FFFFFFFFFFFF";
							}
							if (zet == 50) {
								konn = "7FFFFFFFFFFFF";
							}
							if (zet == 51) {
								konn = "BFFFFFFFFFFFF";
							}
							if (zet == 52) {
								konn = "FFFFFFFFFFFFF";
							}
							if (zet == 53) {
								konn = "3FFFFFFFFFFFFF";
							}
							if (zet == 54) {
								konn = "7FFFFFFFFFFFFF";
							}
							if (zet == 55) {
								konn = "BFFFFFFFFFFFFF";
							}
							if (zet == 56) {
								konn = "FFFFFFFFFFFFFF";
							}
							if (zet == 57) {
								konn = "3FFFFFFFFFFFFFF";
							}
							if (zet == 58) {
								konn = "7FFFFFFFFFFFFFF";
							}
							if (zet == 59) {
								konn = "BFFFFFFFFFFFFFF";
							}
							if (zet == 60) {
								konn = "FFFFFFFFFFFFFFF";
							}
							if (zet == 61) {
								konn = "3FFFFFFFFFFFFFFF";
							}
							if (zet == 62) {
								konn = "7FFFFFFFFFFFFFFF";
							}
							if (zet == 63) {
								konn = "BFFFFFFFFFFFFFFF";
							}
							if (zet == 64) {
								konn = "FFFFFFFFFFFFFFFF";
							}
							if (zet == 65) {
								konn = "3FFFFFFFFFFFFFFFF";
							}
							if (zet == 66) {
								konn = "7FFFFFFFFFFFFFFFF";
							}
							if (zet == 67) {
								konn = "BFFFFFFFFFFFFFFFF";
							}
							if (zet == 68) {
								konn = "FFFFFFFFFFFFFFFFF";
							}
							if (zet == 69) {
								konn = "3FFFFFFFFFFFFFFFFF";
							}
							if (zet == 70) {
								konn = "7FFFFFFFFFFFFFFFFF";
							}
							if (zet == 71) {
								konn = "BFFFFFFFFFFFFFFFFF";
							}
							if (zet == 72) {
								konn = "FFFFFFFFFFFFFFFFFF";
							}
							if (zet == 73) {
								konn = "3FFFFFFFFFFFFFFFFFF";
							}
							if (zet == 74) {
								konn = "7FFFFFFFFFFFFFFFFFF";
							}
							if (zet == 75) {
								konn = "BFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 76) {
								konn = "FFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 77) {
								konn = "3FFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 78) {
								konn = "7FFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 79) {
								konn = "BFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 80) {
								konn = "FFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 81) {
								konn = "3FFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 82) {
								konn = "7FFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 83) {
								konn = "BFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 84) {
								konn = "FFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 85) {
								konn = "3FFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 86) {
								konn = "7FFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 87) {
								konn = "BFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 88) {
								konn = "FFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 89) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 90) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 91) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 92) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 93) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 94) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 95) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 96) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 97) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 98) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 99) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 100) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 101) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 102) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 103) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 104) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 105) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 106) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 107) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 108) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 109) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 110) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 111) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 112) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 113) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 114) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 115) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 116) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 117) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 118) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 119) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 120) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 121) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 122) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 123) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 124) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 125) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 126) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 127) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 128) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 129) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 130) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 131) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 132) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 133) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 134) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 135) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 136) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 137) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 138) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 139) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 140) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 141) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 142) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 143) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 144) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 145) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 146) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 147) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 148) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 149) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 150) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 151) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 152) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 153) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 154) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 155) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 156) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 157) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 158) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 159) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 160) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 161) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 162) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 163) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 164) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 165) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 166) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 167) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 168) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 169) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 170) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 171) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 172) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 173) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 174) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 175) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 176) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 177) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 178) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 179) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 180) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 181) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 182) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 183) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 184) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 185) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 186) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 187) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 188) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 189) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 190) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 191) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 192) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 193) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 194) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 195) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 196) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 197) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 198) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 199) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 200) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 201) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 202) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 203) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 204) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 205) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 206) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 207) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 208) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 209) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 210) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 211) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 212) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 213) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 214) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 215) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 216) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 217) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 218) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 219) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 220) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 221) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 222) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 223) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 224) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 225) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 226) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 227) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 228) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 229) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 230) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 231) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 232) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 233) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 234) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 235) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 236) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 237) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 238) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 239) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 240) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 241) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 242) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 243) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 244) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 245) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 246) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 247) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 248) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 249) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 250) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 251) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 252) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 253) {
								konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 254) {
								konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 255) {
								konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (zet == 256) {
								konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
							}
							if (display > 0) {
								if (next == 1) {
									printf("  ROTOR Random : Private keys random %d (bit)  Range: 1 - 256 (bit) \n", next);
								}
								if (next == 2) {
									printf("  ROTOR Random : Private keys random %d (bit)  Range: 120 - 256 (bit) \n", next);
								}
								if (next == 3) {
									printf("  ROTOR Random : Private keys random %d (bit)  Range: 160 - 256 (bit) \n", next);
								}
								if (next == 4) {
									printf("  ROTOR Random : Private keys random %d (bit)  Range: 200 - 256 (bit) \n", next);
								}

								if (next == 5) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 6) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 7) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 8) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 9) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 10) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 11) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 12) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 13) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 14) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 15) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 16) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 17) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 18) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 19) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 20) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 21) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 22) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 23) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 24) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 25) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 26) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 27) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 28) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 29) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 30) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 31) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 32) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 33) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 34) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 35) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 36) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 37) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 38) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 39) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 40) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 41) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 42) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 43) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 44) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 45) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 46) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 47) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 48) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 49) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 50) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 51) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 52) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 53) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 54) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 55) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 56) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 57) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 58) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 59) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 60) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 61) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 62) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 63) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 64) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 65) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 66) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 67) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 68) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 69) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 70) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 71) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 72) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 73) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 74) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 75) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 76) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 77) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 78) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 79) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 80) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 81) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 82) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 83) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 84) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 85) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 86) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 87) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 88) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 89) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 90) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 91) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 92) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 93) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 94) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 95) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 96) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 97) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 98) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 99) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 100) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 101) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 102) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 103) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 104) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 105) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 106) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 107) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 108) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 109) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 110) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 111) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 112) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 113) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 114) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 115) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 116) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 117) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 118) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 119) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 120) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 121) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 122) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 123) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 124) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 125) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 126) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 127) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 128) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 129) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 130) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 131) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 132) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 133) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 134) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 135) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 136) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 137) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 138) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 139) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 140) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 141) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 142) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 143) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 144) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 145) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 146) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 147) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 148) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 149) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 150) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 151) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 152) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 153) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 154) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 155) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 156) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 157) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 158) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 159) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 160) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 161) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 162) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 163) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 164) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 165) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 166) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 167) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 168) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 169) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 170) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 171) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 172) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 173) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 174) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 175) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 176) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 177) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 178) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 179) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 180) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 181) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 182) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 183) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 184) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 185) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 186) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 187) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 188) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 189) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 190) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 191) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 192) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 193) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 194) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 195) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 196) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 197) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 198) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 199) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 200) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 201) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 202) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 203) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 204) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 205) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 206) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 207) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 208) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 209) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 210) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 211) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 212) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 213) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 214) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 215) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 216) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 217) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 218) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 219) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 220) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 221) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 222) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 223) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 224) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 225) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 226) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 227) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 228) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 229) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 230) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 231) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 232) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 233) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 234) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 235) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 236) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 237) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 238) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 239) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 240) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 241) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 242) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 243) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 244) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 245) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 246) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 247) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 248) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 249) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 250) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 251) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 252) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}

								if (next == 253) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 254) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 255) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
								if (next == 256) {
									printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
								}
							}
						}
						else {

							if (display > 0) {
								if (next == 1) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1 - 256 (bit) \n", next); }
								if (next == 2) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 120 - 256 (bit) \n", next); }
								if (next == 3) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 160 - 256 (bit) \n", next); }
								if (next == 4) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 200 - 256 (bit) \n", next); }

								if (next == 5) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10 <-> 3F \n", next); }
								if (next == 6) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40 <-> 7F \n", next); }
								if (next == 7) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80 <-> BF \n", next); }
								if (next == 8) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0 <-> FF \n", next); }

								if (next == 9) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100 <-> 3FF \n", next); }
								if (next == 10) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400 <-> 7FF \n", next); }
								if (next == 11) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800 <-> BFF \n", next); }
								if (next == 12) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00 <-> FFF \n", next); }

								if (next == 13) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000 <-> 3FFF \n", next); }
								if (next == 14) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000 <-> 7FFF \n", next); }
								if (next == 15) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000 <-> BFFF \n", next); }
								if (next == 16) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000 <-> FFFF \n", next); }

								if (next == 17) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000 <-> 3FFFF \n", next); }
								if (next == 18) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000 <-> 7FFFF \n", next); }
								if (next == 19) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000 <-> BFFFF \n", next); }
								if (next == 20) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000 <-> FFFFF \n", next); }

								if (next == 21) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000 <-> 3FFFFF \n", next); }
								if (next == 22) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000 <-> 7FFFFF \n", next); }
								if (next == 23) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000 <-> BFFFFF \n", next); }
								if (next == 24) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000 <-> FFFFFF \n", next); }

								if (next == 25) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000 <-> 3FFFFFF \n", next); }
								if (next == 26) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000 <-> 7FFFFFF \n", next); }
								if (next == 27) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000 <-> BFFFFFF \n", next); }
								if (next == 28) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000 <-> FFFFFFF \n", next); }

								if (next == 29) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000000 <-> 3FFFFFFF \n", next); }
								if (next == 30) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000000 <-> 7FFFFFFF \n", next); }
								if (next == 31) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000000 <-> BFFFFFFF \n", next); }
								if (next == 32) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000000 <-> FFFFFFFF \n", next); }

								if (next == 33) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000000 <-> 3FFFFFFFF \n", next); }
								if (next == 34) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000000 <-> 7FFFFFFFF \n", next); }
								if (next == 35) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000000 <-> BFFFFFFFF \n", next); }
								if (next == 36) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000000 <-> FFFFFFFFF \n", next); }

								if (next == 37) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000000 <-> 3FFFFFFFFF \n", next); }
								if (next == 38) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000000 <-> 7FFFFFFFFF \n", next); }
								if (next == 39) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000000 <-> BFFFFFFFFF \n", next); }
								if (next == 40) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000000 <-> FFFFFFFFFF \n", next); }

								if (next == 41) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000000000 <-> 3FFFFFFFFFF \n", next); }
								if (next == 42) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000000000 <-> 7FFFFFFFFFF \n", next); }
								if (next == 43) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000000000 <-> BFFFFFFFFFF \n", next); }
								if (next == 44) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000000000 <-> FFFFFFFFFFF \n", next); }

								if (next == 45) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000000000 <-> 3FFFFFFFFFFF \n", next); }
								if (next == 46) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000000000 <-> 7FFFFFFFFFFF \n", next); }
								if (next == 47) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000000000 <-> BFFFFFFFFFFF \n", next); }
								if (next == 48) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000000000 <-> FFFFFFFFFFFF \n", next); }

								if (next == 49) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000000000 <-> 3FFFFFFFFFFFF \n", next); }
								if (next == 50) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000000000 <-> 7FFFFFFFFFFFF \n", next); }
								if (next == 51) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000000000 <-> BFFFFFFFFFFFF \n", next); }
								if (next == 52) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000000000 <-> FFFFFFFFFFFFF \n", next); }

								if (next == 53) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000000000000 <-> 3FFFFFFFFFFFFF \n", next); }
								if (next == 54) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000000000000 <-> 7FFFFFFFFFFFFF \n", next); }
								if (next == 55) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000000000000 <-> BFFFFFFFFFFFFF \n", next); }
								if (next == 56) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000000000000 <-> FFFFFFFFFFFFFF \n", next); }

								if (next == 57) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000000000000 <-> 3FFFFFFFFFFFFFF \n", next); }
								if (next == 58) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000000000000 <-> 7FFFFFFFFFFFFFF \n", next); }
								if (next == 59) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000000000000 <-> BFFFFFFFFFFFFFF \n", next); }
								if (next == 60) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000000000000 <-> FFFFFFFFFFFFFFF \n", next); }

								if (next == 61) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000000000000 <-> 3FFFFFFFFFFFFFFF \n", next); }
								if (next == 62) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000000000000 <-> 7FFFFFFFFFFFFFFF \n", next); }
								if (next == 63) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000000000000 <-> BFFFFFFFFFFFFFFF \n", next); }
								if (next == 64) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000000000000 <-> FFFFFFFFFFFFFFFF \n", next); }

								if (next == 65) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000000000000000 <-> 3FFFFFFFFFFFFFFFF \n", next); }
								if (next == 66) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000000000000000 <-> 7FFFFFFFFFFFFFFFF \n", next); }
								if (next == 67) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000000000000000 <-> BFFFFFFFFFFFFFFFF \n", next); }
								if (next == 68) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000000000000000 <-> FFFFFFFFFFFFFFFFF \n", next); }

								if (next == 69) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000000000000000 <-> 3FFFFFFFFFFFFFFFFF \n", next); }
								if (next == 70) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000000000000000 <-> 7FFFFFFFFFFFFFFFFF \n", next); }
								if (next == 71) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000000000000000 <-> BFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 72) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000000000000000 <-> FFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 73) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000000000000000 <-> 3FFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 74) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000000000000000 <-> 7FFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 75) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000000000000000 <-> BFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 76) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000000000000000 <-> FFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 77) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 78) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 79) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000000000000000000 <-> BFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 80) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000000000000000000 <-> FFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 81) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 82) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 83) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 84) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 85) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 86) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 87) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 88) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 89) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 90) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 91) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 92) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 93) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 94) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 95) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 96) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 97) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 98) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 99) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 100) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 101) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 102) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 103) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 104) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 105) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 106) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 107) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 108) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 109) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 110) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 111) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 112) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 113) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 114) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 115) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 116) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 117) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 118) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 119) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 120) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 121) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 122) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 123) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 124) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 125) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 126) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 127) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 128) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 129) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 130) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 131) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 132) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 133) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 134) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 135) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 136) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 137) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 138) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 139) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 140) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 141) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 142) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 143) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 144) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 145) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 146) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 147) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 148) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 149) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 150) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 151) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 152) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 153) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 154) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 155) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 156) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 157) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 158) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 159) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 160) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 161) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 162) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 163) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 164) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 165) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 166) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 167) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 168) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 169) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 170) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 171) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 172) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 173) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 174) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 175) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 176) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 177) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 178) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 179) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 180) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 181) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 182) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 183) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 184) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 185) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 186) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 187) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 188) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 189) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 190) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 191) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 192) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 193) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 194) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 195) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 196) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 197) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 198) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 199) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 200) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 201) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 202) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 203) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 204) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 205) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 206) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 207) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 208) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 209) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 210) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 211) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 212) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 213) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 214) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 215) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 216) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 217) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 218) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 219) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 220) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 221) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 222) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 223) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 224) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 225) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 226) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 227) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 228) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 229) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 230) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 231) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 232) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 233) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 234) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 235) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 236) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 237) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 238) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 239) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 240) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 241) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 242) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 243) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 244) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 245) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 246) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 247) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 248) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 249) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 250) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 251) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 252) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

								if (next == 253) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 254) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 255) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
								if (next == 256) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							}
						}
					}
				}
                else {

				    if (display > 0) {

						printf("  ROTOR Random : Min %s <~> %s Max\n", rangeStart8.GetBase16().c_str(), rangeEnd.GetBase16().c_str());
				    }

                }

				
				if (display > 0) {
					printf("  Base Key     : Randomly changes %d Private keys every %llu,000,000,000 on the counter\n\n", nbCPUThread, rKey);
				}
			}
		}
	}
	
	
	// CPU Thread
	IntGroup* grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);

	// Group Init
	Int key;// = new Int();
	Point startP;// = new Point();
	getCPUStartingKey(tRangeStart, tRangeEnd, key, startP);

	Int* dx = new Int[CPU_GRP_SIZE / 2 + 1];
	Point* pts = new Point[CPU_GRP_SIZE];

	Int* dy = new Int();
	Int* dyn = new Int();
	Int* _s = new Int();
	Int* _p = new Int();
	Point* pp = new Point();
	Point* pn = new Point();
	grp->Set(dx);

	ph->hasStarted = true;
	ph->rKeyRequest = false;
	
	while (!endOfSearch) {

		if (ph->rKeyRequest) {
			getCPUStartingKey(tRangeStart, tRangeEnd, key, startP);
			ph->rKeyRequest = false;
		}

		// Fill group
		int i;
		int hLength = (CPU_GRP_SIZE / 2 - 1);

		for (i = 0; i < hLength; i++) {
			dx[i].ModSub(&Gn[i].x, &startP.x);
		}
		dx[i].ModSub(&Gn[i].x, &startP.x);  // For the first point
		dx[i + 1].ModSub(&_2Gn.x, &startP.x); // For the next center point

		// Grouped ModInv
		grp->ModInv();

		// We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
		// We compute key in the positive and negative way from the center of the group

		// center point
		pts[CPU_GRP_SIZE / 2] = startP;

		for (i = 0; i < hLength && !endOfSearch; i++) {

			*pp = startP;
			*pn = startP;

			// P = startP + i*G
			dy->ModSub(&Gn[i].y, &pp->y);

			_s->ModMulK1(dy, &dx[i]);       // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
			_p->ModSquareK1(_s);            // _p = pow2(s)

			pp->x.ModNeg();
			pp->x.ModAdd(_p);
			pp->x.ModSub(&Gn[i].x);           // rx = pow2(s) - p1.x - p2.x;

			pp->y.ModSub(&Gn[i].x, &pp->x);
			pp->y.ModMulK1(_s);
			pp->y.ModSub(&Gn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);

			// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
			dyn->Set(&Gn[i].y);
			dyn->ModNeg();
			dyn->ModSub(&pn->y);

			_s->ModMulK1(dyn, &dx[i]);      // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
			_p->ModSquareK1(_s);            // _p = pow2(s)

			pn->x.ModNeg();
			pn->x.ModAdd(_p);
			pn->x.ModSub(&Gn[i].x);          // rx = pow2(s) - p1.x - p2.x;

			pn->y.ModSub(&Gn[i].x, &pn->x);
			pn->y.ModMulK1(_s);
			pn->y.ModAdd(&Gn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);

			pts[CPU_GRP_SIZE / 2 + (i + 1)] = *pp;
			pts[CPU_GRP_SIZE / 2 - (i + 1)] = *pn;

		}

		// First point (startP - (GRP_SZIE/2)*G)
		*pn = startP;
		dyn->Set(&Gn[i].y);
		dyn->ModNeg();
		dyn->ModSub(&pn->y);

		_s->ModMulK1(dyn, &dx[i]);
		_p->ModSquareK1(_s);

		pn->x.ModNeg();
		pn->x.ModAdd(_p);
		pn->x.ModSub(&Gn[i].x);

		pn->y.ModSub(&Gn[i].x, &pn->x);
		pn->y.ModMulK1(_s);
		pn->y.ModAdd(&Gn[i].y);

		pts[0] = *pn;

		// Next start point (startP + GRP_SIZE*G)
		*pp = startP;
		dy->ModSub(&_2Gn.y, &pp->y);

		_s->ModMulK1(dy, &dx[i + 1]);
		_p->ModSquareK1(_s);

		pp->x.ModNeg();
		pp->x.ModAdd(_p);
		pp->x.ModSub(&_2Gn.x);

		pp->y.ModSub(&_2Gn.x, &pp->x);
		pp->y.ModMulK1(_s);
		pp->y.ModSub(&_2Gn.y);
		startP = *pp;

		// Check addresses
		if (useSSE) {
			for (int i = 0; i < CPU_GRP_SIZE && !endOfSearch; i += 4) {
				switch (compMode) {
				case SEARCH_COMPRESSED:
					if (searchMode == (int)SEARCH_MODE_MA) {
						checkMultiAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
					}
					else if (searchMode == (int)SEARCH_MODE_SA) {
						checkSingleAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
					}
					break;
				case SEARCH_UNCOMPRESSED:
					if (searchMode == (int)SEARCH_MODE_MA) {
						checkMultiAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
					}
					else if (searchMode == (int)SEARCH_MODE_SA) {
						checkSingleAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
					}
					break;
				case SEARCH_BOTH:
					if (searchMode == (int)SEARCH_MODE_MA) {
						checkMultiAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
						checkMultiAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
					}
					else if (searchMode == (int)SEARCH_MODE_SA) {
						checkSingleAddressesSSE(true, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
						checkSingleAddressesSSE(false, key, i, pts[i], pts[i + 1], pts[i + 2], pts[i + 3]);
					}
					break;
				}
			}
		}
		else {
			if (coinType == COIN_BTC) {
				for (int i = 0; i < CPU_GRP_SIZE && !endOfSearch; i++) {
					switch (compMode) {
					case SEARCH_COMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, pts[i]);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, pts[i]);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, pts[i]);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, pts[i]);
							break;
						default:
							break;
						}
						break;
					case SEARCH_UNCOMPRESSED:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(false, key, i, pts[i]);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(false, key, i, pts[i]);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(false, key, i, pts[i]);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(false, key, i, pts[i]);
							break;
						default:
							break;
						}
						break;
					case SEARCH_BOTH:
						switch (searchMode) {
						case (int)SEARCH_MODE_MA:
							checkMultiAddresses(true, key, i, pts[i]);
							checkMultiAddresses(false, key, i, pts[i]);
							break;
						case (int)SEARCH_MODE_SA:
							checkSingleAddress(true, key, i, pts[i]);
							checkSingleAddress(false, key, i, pts[i]);
							break;
						case (int)SEARCH_MODE_MX:
							checkMultiXPoints(true, key, i, pts[i]);
							checkMultiXPoints(false, key, i, pts[i]);
							break;
						case (int)SEARCH_MODE_SX:
							checkSingleXPoint(true, key, i, pts[i]);
							checkSingleXPoint(false, key, i, pts[i]);
							break;
						default:
							break;
						}
						break;
					}
				}
			}
			else {
				for (int i = 0; i < CPU_GRP_SIZE && !endOfSearch; i++) {
					switch (searchMode) {
					case (int)SEARCH_MODE_MA:
						checkMultiAddressesETH(key, i, pts[i]);
						break;
					case (int)SEARCH_MODE_SA:
						checkSingleAddressETH(key, i, pts[i]);
						break;
					default:
						break;
					}
				}
			}
		}
		key.Add((uint64_t)CPU_GRP_SIZE);
		counters[thId] += CPU_GRP_SIZE; // Point
	}
	ph->isRunning = false;

	delete grp;
	delete[] dx;
	delete[] pts;

	delete dy;
	delete dyn;
	delete _s;
	delete _p;
	delete pp;
	delete pn;
}

// ----------------------------------------------------------------------------

void Rotor::getGPUStartingKeys(Int & tRangeStart, Int & tRangeEnd, int groupSize, int nbThread, Int * keys, Point * p)
{
	if (rKey > 0) {
		
		if (rangeDiff2.GetBitLength() > 10) {
			
			if (rKeyCount2 == 0) {
				if (display > 0) {
					printf("  Base Key     : Randomly changes %d start Private keys every %llu,000,000,000 on the counter\n\n", nbThread, rKey);
					printf("  ROTOR Random : Min %s <~> %s Max\n\n", tRangeStart.GetBase16().c_str(), tRangeEnd.GetBase16().c_str());
				}
			}
			
			for (int i = 0; i < nbThread; i++) {
				
				gpucores = i;
				keys[i].Set(&rangeStart8);
				Int ddv;
				int sak = 1 + rand() % 3;

				if (sak == 1) {
					ddv.Rand(&rangeDiff2);
					keys[i].Add(&ddv);
					rhex = keys[i];
				}
				if (sak == 2) {
					ddv.Rand(&rangeDiff2);
					keys[i].Add(&ddv);
					rhex = keys[i];
				}
				
				if (sak == 3) {

					int stt = 1 + rand() % 100;
					
					if (stt < 90) {
						int fgg = rangeDiff2.GetBitLength();
						ddv.Rand(fgg);
						keys[i].Add(&ddv);
						rhex = keys[i];
					
					}
					else {

						int fgg = rangeDiff2.GetBitLength();
						int sakr = 1 + rand() % fgg;
						ddv.Rand(sakr);
						keys[i].Add(&ddv);
						rhex = keys[i];
					}
				}

				if (display > 0) {
					printf("\r  [Thread: %d]   [%s] ", i, keys[i].GetBase16().c_str());
				}
				Int k(keys + i);
				k.Add((uint64_t)(groupSize / 2));
				p[i] = secp->ComputePublicKey(&k);
			}
		}
		else {
			if (next > 0) {

				if (rKeyCount2 == 0) {

					if (next > 256) {
						printf("\n  ROTOR Random : Are you serious %d bit ??? \n", next);
						exit(1);
					}
					if (zet > 256) {
						printf("\n  ROTOR Random : Are you serious -z %d bit ??? \n", zet);
						exit(1);
					}
					if (zet < 1) {

						if (display > 0) {
							if (next == 1) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1 - 256 (bit) \n", next); }
							if (next == 2) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 120 - 256 (bit) \n", next); }
							if (next == 3) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 160 - 256 (bit) \n", next); }
							if (next == 4) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 200 - 256 (bit) \n", next); }

							if (next == 5) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10 <-> 3F \n", next); }
							if (next == 6) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40 <-> 7F \n", next); }
							if (next == 7) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80 <-> BF \n", next); }
							if (next == 8) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0 <-> FF \n", next); }

							if (next == 9) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100 <-> 3FF \n", next); }
							if (next == 10) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400 <-> 7FF \n", next); }
							if (next == 11) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800 <-> BFF \n", next); }
							if (next == 12) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00 <-> FFF \n", next); }

							if (next == 13) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000 <-> 3FFF \n", next); }
							if (next == 14) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000 <-> 7FFF \n", next); }
							if (next == 15) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000 <-> BFFF \n", next); }
							if (next == 16) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000 <-> FFFF \n", next); }

							if (next == 17) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000 <-> 3FFFF \n", next); }
							if (next == 18) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000 <-> 7FFFF \n", next); }
							if (next == 19) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000 <-> BFFFF \n", next); }
							if (next == 20) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000 <-> FFFFF \n", next); }

							if (next == 21) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000 <-> 3FFFFF \n", next); }
							if (next == 22) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000 <-> 7FFFFF \n", next); }
							if (next == 23) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000 <-> BFFFFF \n", next); }
							if (next == 24) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000 <-> FFFFFF \n", next); }

							if (next == 25) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000 <-> 3FFFFFF \n", next); }
							if (next == 26) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000 <-> 7FFFFFF \n", next); }
							if (next == 27) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000 <-> BFFFFFF \n", next); }
							if (next == 28) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000 <-> FFFFFFF \n", next); }

							if (next == 29) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000000 <-> 3FFFFFFF \n", next); }
							if (next == 30) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000000 <-> 7FFFFFFF \n", next); }
							if (next == 31) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000000 <-> BFFFFFFF \n", next); }
							if (next == 32) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000000 <-> FFFFFFFF \n", next); }

							if (next == 33) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000000 <-> 3FFFFFFFF \n", next); }
							if (next == 34) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000000 <-> 7FFFFFFFF \n", next); }
							if (next == 35) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000000 <-> BFFFFFFFF \n", next); }
							if (next == 36) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000000 <-> FFFFFFFFF \n", next); }

							if (next == 37) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000000 <-> 3FFFFFFFFF \n", next); }
							if (next == 38) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000000 <-> 7FFFFFFFFF \n", next); }
							if (next == 39) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000000 <-> BFFFFFFFFF \n", next); }
							if (next == 40) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000000 <-> FFFFFFFFFF \n", next); }

							if (next == 41) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000000000 <-> 3FFFFFFFFFF \n", next); }
							if (next == 42) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000000000 <-> 7FFFFFFFFFF \n", next); }
							if (next == 43) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000000000 <-> BFFFFFFFFFF \n", next); }
							if (next == 44) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000000000 <-> FFFFFFFFFFF \n", next); }

							if (next == 45) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000000000 <-> 3FFFFFFFFFFF \n", next); }
							if (next == 46) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000000000 <-> 7FFFFFFFFFFF \n", next); }
							if (next == 47) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000000000 <-> BFFFFFFFFFFF \n", next); }
							if (next == 48) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000000000 <-> FFFFFFFFFFFF \n", next); }

							if (next == 49) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000000000 <-> 3FFFFFFFFFFFF \n", next); }
							if (next == 50) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000000000 <-> 7FFFFFFFFFFFF \n", next); }
							if (next == 51) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000000000 <-> BFFFFFFFFFFFF \n", next); }
							if (next == 52) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000000000 <-> FFFFFFFFFFFFF \n", next); }

							if (next == 53) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000000000000 <-> 3FFFFFFFFFFFFF \n", next); }
							if (next == 54) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000000000000 <-> 7FFFFFFFFFFFFF \n", next); }
							if (next == 55) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000000000000 <-> BFFFFFFFFFFFFF \n", next); }
							if (next == 56) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000000000000 <-> FFFFFFFFFFFFFF \n", next); }

							if (next == 57) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000000000000 <-> 3FFFFFFFFFFFFFF \n", next); }
							if (next == 58) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000000000000 <-> 7FFFFFFFFFFFFFF \n", next); }
							if (next == 59) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000000000000 <-> BFFFFFFFFFFFFFF \n", next); }
							if (next == 60) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000000000000 <-> FFFFFFFFFFFFFFF \n", next); }

							if (next == 61) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000000000000 <-> 3FFFFFFFFFFFFFFF \n", next); }
							if (next == 62) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000000000000 <-> 7FFFFFFFFFFFFFFF \n", next); }
							if (next == 63) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000000000000 <-> BFFFFFFFFFFFFFFF \n", next); }
							if (next == 64) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000000000000 <-> FFFFFFFFFFFFFFFF \n", next); }

							if (next == 65) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000000000000000 <-> 3FFFFFFFFFFFFFFFF \n", next); }
							if (next == 66) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000000000000000 <-> 7FFFFFFFFFFFFFFFF \n", next); }
							if (next == 67) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000000000000000 <-> BFFFFFFFFFFFFFFFF \n", next); }
							if (next == 68) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000000000000000 <-> FFFFFFFFFFFFFFFFF \n", next); }

							if (next == 69) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000000000000000 <-> 3FFFFFFFFFFFFFFFFF \n", next); }
							if (next == 70) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000000000000000 <-> 7FFFFFFFFFFFFFFFFF \n", next); }
							if (next == 71) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000000000000000 <-> BFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 72) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000000000000000 <-> FFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 73) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000000000000000 <-> 3FFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 74) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000000000000000 <-> 7FFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 75) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000000000000000 <-> BFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 76) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000000000000000 <-> FFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 77) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 10000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 78) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 40000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 79) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 80000000000000000000 <-> BFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 80) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C0000000000000000000 <-> FFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 81) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 100000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 82) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 400000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 83) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 800000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 84) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C00000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 85) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 1000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 86) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 4000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 87) { printf("  ROTOR Random : Private keys random %d (bit)  Range: 8000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 88) { printf("  ROTOR Random : Private keys random %d (bit)  Range: C000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 89) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 90) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 91) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 92) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 93) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 94) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 95) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 96) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 97) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 98) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 99) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 100) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 101) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 102) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 103) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 104) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 105) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 106) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 107) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 108) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 109) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 110) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 111) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 112) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 113) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 114) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 115) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 116) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 117) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 118) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 119) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 120) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 121) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 122) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 123) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 124) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 125) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 126) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 127) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 128) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 129) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 130) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 131) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 132) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 133) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 134) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 135) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 136) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 137) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 138) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 139) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 140) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 141) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 142) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 143) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 144) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 145) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 146) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 147) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 148) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 149) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 150) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 151) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 152) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 153) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 154) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 155) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 156) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 157) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 158) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 159) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 160) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 161) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 162) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 163) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 164) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 165) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 166) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 167) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 168) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 169) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 170) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 171) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 172) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 173) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 174) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 175) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 176) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 177) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 178) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 179) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 180) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 181) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 182) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 183) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 184) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 185) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 186) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 187) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 188) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 189) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 190) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 191) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 192) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 193) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 194) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 195) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 196) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 197) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 198) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 199) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 200) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 201) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 202) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 203) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 204) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 205) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 206) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 207) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 208) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 209) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 210) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 211) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 212) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 213) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 214) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 215) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 216) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 217) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 218) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 219) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 220) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 221) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 222) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 223) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 224) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 225) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 226) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 227) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 228) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 229) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 230) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 231) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 232) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 233) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 234) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 235) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 236) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 237) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 238) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 239) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 240) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 241) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 242) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 243) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 244) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 245) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 10000000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 246) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 40000000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 247) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 80000000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 248) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C0000000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 249) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 100000000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 250) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 400000000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 251) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 800000000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 252) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C00000000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

							if (next == 253) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 1000000000000000000000000000000000000000000000000000000000000000 <-> 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 254) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 4000000000000000000000000000000000000000000000000000000000000000 <-> 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 255) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : 8000000000000000000000000000000000000000000000000000000000000000 <-> BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }
							if (next == 256) { printf("  ROTOR Random : Private keys random %d (bit)  \n  Range        : C000000000000000000000000000000000000000000000000000000000000000 <-> FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF \n", next); }

						}
					}
					else {

						string konn;

						if (zet == 5) {
							konn = "3F";
						}
						if (zet == 6) {
							konn = "7F";
						}
						if (zet == 7) {
							konn = "BF";
						}
						if (zet == 8) {
							konn = "FF";
						}
						if (zet == 9) {
							konn = "3FF";
						}
						if (zet == 10) {
							konn = "7FF";
						}
						if (zet == 11) {
							konn = "BFF";
						}
						if (zet == 12) {
							konn = "FFF";
						}
						if (zet == 13) {
							konn = "3FFF";
						}
						if (zet == 14) {
							konn = "7FFF";
						}
						if (zet == 15) {
							konn = "BFFF";
						}
						if (zet == 16) {
							konn = "FFFF";
						}
						if (zet == 17) {
							konn = "3FFFF";
						}
						if (zet == 18) {
							konn = "7FFFF";
						}
						if (zet == 19) {
							konn = "BFFFF";
						}
						if (zet == 20) {
							konn = "FFFFF";
						}
						if (zet == 21) {
							konn = "3FFFFF";
						}
						if (zet == 22) {
							konn = "7FFFFF";
						}
						if (zet == 23) {
							konn = "BFFFFF";
						}
						if (zet == 24) {
							konn = "FFFFFF";
						}
						if (zet == 25) {
							konn = "3FFFFFF";
						}
						if (zet == 26) {
							konn = "7FFFFFF";
						}
						if (zet == 27) {
							konn = "BFFFFFF";
						}
						if (zet == 28) {
							konn = "FFFFFFF";
						}
						if (zet == 29) {
							konn = "3FFFFFFF";
						}
						if (zet == 30) {
							konn = "7FFFFFFF";
						}
						if (zet == 31) {
							konn = "BFFFFFFF";
						}
						if (zet == 32) {
							konn = "FFFFFFFF";
						}
						if (zet == 33) {
							konn = "3FFFFFFFF";
						}
						if (zet == 34) {
							konn = "7FFFFFFFF";
						}
						if (zet == 35) {
							konn = "BFFFFFFFF";
						}
						if (zet == 36) {
							konn = "FFFFFFFFF";
						}
						if (zet == 37) {
							konn = "3FFFFFFFFF";
						}
						if (zet == 38) {
							konn = "7FFFFFFFFF";
						}
						if (zet == 39) {
							konn = "BFFFFFFFFF";
						}
						if (zet == 40) {
							konn = "FFFFFFFFFF";
						}
						if (zet == 41) {
							konn = "3FFFFFFFFFF";
						}
						if (zet == 42) {
							konn = "7FFFFFFFFFF";
						}
						if (zet == 43) {
							konn = "BFFFFFFFFFF";
						}
						if (zet == 44) {
							konn = "FFFFFFFFFFF";
						}
						if (zet == 45) {
							konn = "3FFFFFFFFFFF";
						}
						if (zet == 46) {
							konn = "7FFFFFFFFFFF";
						}
						if (zet == 47) {
							konn = "BFFFFFFFFFFF";
						}
						if (zet == 48) {
							konn = "FFFFFFFFFFFF";
						}
						if (zet == 49) {
							konn = "3FFFFFFFFFFFF";
						}
						if (zet == 50) {
							konn = "7FFFFFFFFFFFF";
						}
						if (zet == 51) {
							konn = "BFFFFFFFFFFFF";
						}
						if (zet == 52) {
							konn = "FFFFFFFFFFFFF";
						}
						if (zet == 53) {
							konn = "3FFFFFFFFFFFFF";
						}
						if (zet == 54) {
							konn = "7FFFFFFFFFFFFF";
						}
						if (zet == 55) {
							konn = "BFFFFFFFFFFFFF";
						}
						if (zet == 56) {
							konn = "FFFFFFFFFFFFFF";
						}
						if (zet == 57) {
							konn = "3FFFFFFFFFFFFFF";
						}
						if (zet == 58) {
							konn = "7FFFFFFFFFFFFFF";
						}
						if (zet == 59) {
							konn = "BFFFFFFFFFFFFFF";
						}
						if (zet == 60) {
							konn = "FFFFFFFFFFFFFFF";
						}
						if (zet == 61) {
							konn = "3FFFFFFFFFFFFFFF";
						}
						if (zet == 62) {
							konn = "7FFFFFFFFFFFFFFF";
						}
						if (zet == 63) {
							konn = "BFFFFFFFFFFFFFFF";
						}
						if (zet == 64) {
							konn = "FFFFFFFFFFFFFFFF";
						}
						if (zet == 65) {
							konn = "3FFFFFFFFFFFFFFFF";
						}
						if (zet == 66) {
							konn = "7FFFFFFFFFFFFFFFF";
						}
						if (zet == 67) {
							konn = "BFFFFFFFFFFFFFFFF";
						}
						if (zet == 68) {
							konn = "FFFFFFFFFFFFFFFFF";
						}
						if (zet == 69) {
							konn = "3FFFFFFFFFFFFFFFFF";
						}
						if (zet == 70) {
							konn = "7FFFFFFFFFFFFFFFFF";
						}
						if (zet == 71) {
							konn = "BFFFFFFFFFFFFFFFFF";
						}
						if (zet == 72) {
							konn = "FFFFFFFFFFFFFFFFFF";
						}
						if (zet == 73) {
							konn = "3FFFFFFFFFFFFFFFFFF";
						}
						if (zet == 74) {
							konn = "7FFFFFFFFFFFFFFFFFF";
						}
						if (zet == 75) {
							konn = "BFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 76) {
							konn = "FFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 77) {
							konn = "3FFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 78) {
							konn = "7FFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 79) {
							konn = "BFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 80) {
							konn = "FFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 81) {
							konn = "3FFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 82) {
							konn = "7FFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 83) {
							konn = "BFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 84) {
							konn = "FFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 85) {
							konn = "3FFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 86) {
							konn = "7FFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 87) {
							konn = "BFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 88) {
							konn = "FFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 89) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 90) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 91) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 92) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 93) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 94) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 95) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 96) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 97) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 98) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 99) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 100) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 101) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 102) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 103) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 104) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 105) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 106) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 107) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 108) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 109) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 110) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 111) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 112) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 113) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 114) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 115) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 116) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 117) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 118) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 119) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 120) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 121) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 122) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 123) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 124) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 125) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 126) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 127) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 128) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 129) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 130) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 131) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 132) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 133) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 134) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 135) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 136) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 137) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 138) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 139) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 140) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 141) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 142) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 143) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 144) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 145) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 146) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 147) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 148) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 149) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 150) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 151) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 152) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 153) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 154) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 155) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 156) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 157) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 158) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 159) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 160) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 161) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 162) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 163) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 164) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 165) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 166) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 167) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 168) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 169) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 170) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 171) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 172) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 173) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 174) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 175) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 176) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 177) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 178) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 179) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 180) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 181) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 182) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 183) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 184) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 185) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 186) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 187) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 188) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 189) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 190) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 191) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 192) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 193) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 194) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 195) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 196) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 197) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 198) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 199) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 200) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 201) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 202) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 203) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 204) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 205) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 206) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 207) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 208) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 209) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 210) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 211) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 212) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 213) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 214) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 215) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 216) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 217) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 218) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 219) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 220) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 221) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 222) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 223) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 224) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 225) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 226) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 227) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 228) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 229) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 230) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 231) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 232) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 233) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 234) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 235) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 236) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 237) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 238) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 239) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 240) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 241) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 242) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 243) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 244) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 245) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 246) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 247) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 248) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 249) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 250) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 251) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 252) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 253) {
							konn = "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 254) {
							konn = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 255) {
							konn = "BFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}
						if (zet == 256) {
							konn = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
						}

						if (display > 0) {

							if (next == 1) {
								printf("  ROTOR Random : Private keys random %d (bit)  Range: 1 - 256 (bit) \n", next);
							}
							if (next == 2) {
								printf("  ROTOR Random : Private keys random %d (bit)  Range: 120 - 256 (bit) \n", next);
							}
							if (next == 3) {
								printf("  ROTOR Random : Private keys random %d (bit)  Range: 160 - 256 (bit) \n", next);
							}
							if (next == 4) {
								printf("  ROTOR Random : Private keys random %d (bit)  Range: 200 - 256 (bit) \n", next);
							}

							if (next == 5) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 6) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 7) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 8) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 9) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 10) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 11) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 12) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 13) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 14) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 15) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 16) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 17) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 18) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 19) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 20) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 21) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 22) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 23) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 24) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 25) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 26) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 27) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 28) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 29) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 30) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 31) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 32) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 33) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 34) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 35) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 36) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 37) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 38) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 39) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 40) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 41) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 42) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 43) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 44) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 45) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 46) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 47) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 48) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 49) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 50) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 51) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 52) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 53) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 54) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 55) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 56) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 57) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 58) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 59) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 60) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 61) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 62) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 63) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 64) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 65) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 66) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 67) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 68) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 69) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 70) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 71) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 72) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 73) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 74) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 75) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 76) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 77) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 10000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 78) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 40000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 79) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 80000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 80) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C0000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 81) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 100000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 82) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 400000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 83) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 800000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 84) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C00000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 85) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 1000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 86) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 4000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 87) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: 8000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 88) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) Range: C000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 89) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 90) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 91) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 92) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 93) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 94) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 95) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 96) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 97) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 98) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 99) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 100) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 101) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 102) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 103) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 104) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 105) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 106) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 107) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 108) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 109) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 110) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 111) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 112) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 113) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 114) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 115) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 116) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 117) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 118) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 119) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 120) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 121) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 122) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 123) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 124) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 125) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 126) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 127) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 128) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 129) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 130) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 131) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 132) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 133) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 134) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 135) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 136) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 137) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 138) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 139) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 140) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 141) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 142) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 143) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 144) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 145) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 146) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 147) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 148) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 149) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 150) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 151) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 152) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 153) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 154) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 155) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 156) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 157) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 158) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 159) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 160) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 161) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 162) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 163) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 164) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 165) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 166) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 167) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 168) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 169) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 170) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 171) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 172) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 173) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 174) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 175) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 176) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 177) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 178) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 179) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 180) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 181) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 182) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 183) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 184) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 185) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 186) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 187) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 188) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 189) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 190) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 191) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 192) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 193) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 194) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 195) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 196) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 197) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 198) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 199) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 200) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 201) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 202) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 203) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 204) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 205) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 206) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 207) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 208) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 209) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 210) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 211) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 212) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 213) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 214) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 215) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 216) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 217) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 218) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 219) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 220) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 221) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 222) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 223) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 224) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 225) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 226) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 227) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 228) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 229) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 230) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 231) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 232) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 233) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 234) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 235) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 236) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 237) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 238) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 239) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 240) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 241) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 242) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 243) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 244) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 245) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 10000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 246) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 40000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 247) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 80000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 248) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C0000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 249) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 100000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 250) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 400000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 251) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 800000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 252) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C00000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}

							if (next == 253) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 1000000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 254) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 4000000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 255) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : 8000000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
							if (next == 256) {
								printf("  ROTOR Random : Private keys random %d <~> %d (bit) \n  Range        : C000000000000000000000000000000000000000000000000000000000000000 <~> %s \n", next, zet, konn.c_str());
							}
						}
					}
					if (display > 0) {
						printf("  Base Key     : Randomly changes %d start Private keys every %llu,000,000,000 on the counter\n\n", nbThread, rKey);
					}
				}

				for (int i = 0; i < nbThread; i++) {
					
					gpucores = i;
					int next2 = 0;

					if (zet < 1) {
						next2 = next;
					}
					else {
						if (zet <= next) {
							printf("\n  ROTOR Random : Are you serious -n %d (start) -z %d (end) ??? \n  The start must be less than the end \n", next, zet);
							exit(1);
						}
						int dfs = zet - next;

						if (dfs == 1) {
							next2 = next + rand() % 2;
						}
						else {
							next2 = next + rand() % dfs;
							next2 = next2 + rand() % 2;
						}
					}

					if (next2 == 1) {

						int N = 20 + rand() % 45;

						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 2) {
						int N = 30 + rand() % 35;

						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 3) {
						int N = 40 + rand() % 25;

						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 4) {
						int N = 50 + rand() % 15;

						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 5) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 1;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 6) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 1;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 7) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 1;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 8) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 1;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 9) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 2;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 10) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 2;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 11) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 2;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 12) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 2;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 13) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 3;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 14) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 3;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 15) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 3;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 16) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 3;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 17) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 4;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 18) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 4;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 19) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 4;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 20) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 4;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 21) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 5;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 22) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 5;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 23) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 5;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 24) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 5;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 25) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 6;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 26) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 6;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 27) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 6;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 28) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 6;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 29) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 7;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 30) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 7;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 31) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 7;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 32) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 7;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 33) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 8;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 34) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 8;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 35) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 8;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 36) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 8;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 37) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 9;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 38) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 9;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 39) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 9;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 40) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 9;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 41) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 10;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 42) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 10;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 43) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 10;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 44) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 10;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 45) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 11;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 46) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 11;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 47) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 11;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 48) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 11;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 49) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 12;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 50) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 12;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 51) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 12;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 52) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 12;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 53) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 13;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 54) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 13;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 55) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 13;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 56) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 13;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 57) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 14;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 58) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 14;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 59) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 14;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 60) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 14;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 61) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 15;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 62) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 15;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 63) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 15;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 64) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 15;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 65) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 16;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 66) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 16;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 67) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 16;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 68) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 16;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 69) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 17;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 70) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 17;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 71) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 17;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 72) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 17;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 73) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 18;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 74) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 18;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 75) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 18;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 76) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 18;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 77) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 19;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 78) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 19;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 79) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 19;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 80) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 19;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 81) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 20;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 82) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 20;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 83) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 20;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 84) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 20;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 85) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 21;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 86) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 21;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 87) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 21;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 88) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 21;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 89) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 22;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 90) {
						int N2 = 4;
						char str2[]{ "4567" };
						int strN2 = 1;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 22;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 91) {
						int N2 = 4;
						char str2[]{ "89ab" };
						int strN2 = 1;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 22;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 92) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 22;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 93) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 23;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 94) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 23;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 95) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 23;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 96) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 23;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 97) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 24;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 98) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 24;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 99) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 24;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 100) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 24;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 101) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 25;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 102) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 25;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 103) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 25;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 104) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 25;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 105) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 26;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 106) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 26;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 107) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 26;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 108) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 26;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 109) {
						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 27;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 110) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 27;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 111) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 27;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 112) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 27;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 113) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 28;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 114) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 28;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 115) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 28;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 116) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 28;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 117) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 29;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 118) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 29;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 119) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 29;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 120) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 29;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 121) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 30;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 122) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 30;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 123) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 30;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 124) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 30;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 125) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 31;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 126) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 31;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 127) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 31;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 128) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 31;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 129) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 32;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 130) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 32;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 131) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 32;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 132) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 32;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 133) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 33;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 134) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 33;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 135) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 33;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 136) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 33;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 137) {
						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 34;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 138) {
						int N2 = 4;
						char str2[]{ "4567" };
						int strN2 = 1;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 34;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 139) {

						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 34;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 140) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 34;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 141) {
						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 35;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 142) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 35;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 143) {

						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 35;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 144) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 35;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 145) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 36;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 146) {

						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 36;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 147) {

						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 36;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 148) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 36;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 149) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 37;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 150) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 37;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 151) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 37;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 152) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 37;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 153) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 38;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 154) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 38;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 155) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 38;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 156) {
						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 38;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 157) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 39;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 158) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 39;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 159) {

						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 39;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 160) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 39;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 161) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 40;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 162) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 40;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 163) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 40;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 164) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 40;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 165) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 41;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 166) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 41;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 167) {

						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 41;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 168) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 41;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 169) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 42;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 170) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 42;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 171) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 42;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 172) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 42;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 173) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 43;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 174) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 43;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 175) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 43;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 176) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 43;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 177) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 44;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 178) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 44;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 179) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 44;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 180) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 44;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 181) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 45;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 182) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 45;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 183) {

						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 45;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 184) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 45;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 185) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 46;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 186) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 46;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 187) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 46;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 188) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 46;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 189) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 47;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 190) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 47;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 191) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 47;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 192) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 47;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 193) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 48;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 194) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 48;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 195) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 48;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 196) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 48;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 197) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 49;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 198) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 49;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 199) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 49;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 200) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 49;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 201) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 50;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 202) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 50;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 203) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 50;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 204) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 50;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 205) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 51;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 206) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 51;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 207) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 51;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 208) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 51;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 209) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 52;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 210) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 52;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 211) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 52;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 212) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 52;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 213) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 53;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 214) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 53;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 215) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 53;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 216) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 53;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 217) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 54;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 218) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 54;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 219) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 54;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 220) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 54;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 221) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 55;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 222) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 55;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 223) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 55;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 224) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 55;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 225) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 56;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 226) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 56;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 227) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 56;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 228) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 56;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 229) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 57;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 230) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 57;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 231) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 57;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 232) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 57;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 233) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 58;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 234) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 58;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 235) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 58;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 236) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 58;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 237) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 59;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 238) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 59;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 239) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 59;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 240) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 59;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}

					if (next2 == 241) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 60;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 242) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 60;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 243) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 60;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 244) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 60;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 245) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 61;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 246) {

						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 61;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 247) {

						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 61;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 248) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 61;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 249) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 62;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 250) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 62;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);
					}
					if (next2 == 251) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 62;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);


					}
					if (next2 == 252) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 62;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 253) {

						int N2 = 1;
						char str2[]{ "123" };
						int strN2 = 3;

						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 63;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);


					}
					if (next2 == 254) {
						int N2 = 1;
						char str2[]{ "4567" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 63;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 255) {
						int N2 = 1;
						char str2[]{ "89ab" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 63;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (next2 == 256) {

						int N2 = 1;
						char str2[]{ "cdef" };
						int strN2 = 4;
						char* pass2 = new char[N2 + 1];
						for (int i = 0; i < N2; i++)
						{
							pass2[i] = str2[rand() % strN2];
						}
						pass2[N2] = 0;

						int N = 63;
						char str[]{ "0123456789abcdef" };
						int strN = 16;
						char* pass = new char[N + 1];
						for (int i = 0; i < N; i++)
						{
							pass[i] = str[rand() % strN];
						}
						pass[N] = 0;
						std::stringstream ss;
						ss << pass2 << pass;
						std::string input = ss.str();
						char* cstr = &input[0];
						keys[i].SetBase16(cstr);
						rhex.SetBase16(cstr);

					}
					if (display > 0) {
						printf("\r  [Thread: %d]   [%s] ", i, keys[i].GetBase16().c_str());
					}

					Int k(keys + i);
					k.Add((uint64_t)(groupSize / 2));
					p[i] = secp->ComputePublicKey(&k);
				}
			}
			else {
				if (rKeyCount2 == 0) {
					if (display > 0) {
						printf("  Rotor Random : Default valid sha256 Private keys random 95%% (252-256) bit + 5%% (248-252) bit\n");
						printf("  Base Key     : Randomly changes %d start Private keys every %llu,000,000,000 on the counter\n\n", nbThread, rKey);
					}
				}

				for (int i = 0; i < nbThread; i++) {
					
					gpucores = i;
					int N = rand() % 56 + 8;
					char str[]{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$&()*+,-.:<=>?@_~" };
					int strN = 80;
					char* pass = new char[N + 1];
					for (int i = 0; i < N; i++)
					{
						pass[i] = str[rand() % strN];
					}
					pass[N] = 0;

					string nos3 = sha256(pass);
					char* cstr2 = &nos3[0];

					keys[i].SetBase16(cstr2);
					if (display > 0) {
						printf("\r  [Thread: %d]   [%s] ", i, keys[i].GetBase16().c_str());
					}

					rhex.SetBase16(cstr2);

					Int k(keys + i);
					k.Add((uint64_t)(groupSize / 2));
					p[i] = secp->ComputePublicKey(&k);
				}
			}
		}
	}
	else {
		
		Int tThreads;
		tThreads.SetInt32(nbThread);
		Int tRangeDiff(tRangeEnd);
		Int tRangeStart2(tRangeStart);
		Int tRangeEnd2(tRangeStart);

		tRangeDiff.Set(&tRangeEnd);
		tRangeDiff.Sub(&tRangeStart);
		razn = tRangeDiff;

		tRangeDiff.Div(&tThreads);
		
		int rangeShowThreasold = 3;
		int rangeShowCounter = 0;
		uint64_t nextt = 0;
		if (value777 > 1) {
			nextt = value777 / nbThread;
			tRangeStart2.Add(nextt);
		}
		if (next > 0) { 

			if (display > 0) {
				printf("  Rotor info   : Save checkpoints every %d minutes. For continue range, run the bat file Rotor-Cuda_Continue.bat \n", next);
			}
		}
		gir.Set(&rangeDiff2);
		Int reh;
		uint64_t nextt99;
		nextt99 = value777 * 1;
		reh.Add(nextt99);
		gir.Sub(&reh);

		if (display > 0) {
			if (value777 > 1) {
				printf("\n  Rotor info   : Continuation... Divide the remaining range %s (%d bit) into GPU %d threads \n\n", gir.GetBase16().c_str(), gir.GetBitLength(), nbThread);
			}
			else {
				printf("\n  Rotor info   : Divide the range %s (%d bit) into GPU %d threads \n\n", rangeDiff2.GetBase16().c_str(), gir.GetBitLength(), nbThread);
			}
		}
		
		for (int i = 0; i < nbThread + 1; i++) {
			gpucores = i;
			tRangeEnd2.Set(&tRangeStart2);
			tRangeEnd2.Add(&tRangeDiff);

			keys[i].Set(&tRangeStart2);
			if (i == 0) {
				if (display > 0) {
					printf("  Thread 00000 : %s ->", keys[i].GetBase16().c_str());
				}
			}
			Int dobb;
			dobb.Set(&tRangeStart2);
			dobb.Add(&tRangeDiff);
			dobb.Sub(nextt);
			if (display > 0) {

				if (i == 0) {
					printf(" %s \n", dobb.GetBase16().c_str());
				}
				if (i == 1) {
					printf("  Thread 00001 : %s -> %s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				}
				if (i == 2) {
					printf("  Thread 00002 : %s -> %s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				}
				if (i == 3) {
					printf("  Thread 00003 : %s -> %s \n", tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
					printf("           ... : \n");
				}
				if (i == nbThread - 2) {
					printf("  Thread %d : %s -> %s \n", i, tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				}
				if (i == nbThread - 1) {
					printf("  Thread %d : %s -> %s \n", i, tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				}
				if (i == nbThread) {
					printf("  Thread %d : %s -> %s \n\n", i, tRangeStart2.GetBase16().c_str(), dobb.GetBase16().c_str());
				}
			}
			tRangeStart2.Add(&tRangeDiff);
			Int k(keys + i);
			k.Add((uint64_t)(groupSize / 2));
			p[i] = secp->ComputePublicKey(&k);
		}
	}
}

void Rotor::FindKeyGPU(TH_PARAM * ph)
{

	bool ok = true;

#ifdef WITHGPU

	// Global init
	int thId = ph->threadId;
	Int tRangeStart = ph->rangeStart;
	Int tRangeEnd = ph->rangeEnd;

	GPUEngine* g;
	switch (searchMode) {
	case (int)SEARCH_MODE_MA:
	case (int)SEARCH_MODE_MX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			BLOOM_N, bloom->get_bits(), bloom->get_hashes(), bloom->get_bf(), DATA, TOTAL_COUNT, (rKey != 0));
		break;
	case (int)SEARCH_MODE_SA:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			hash160Keccak, (rKey != 0));
		break;
	case (int)SEARCH_MODE_SX:
		g = new GPUEngine(secp, ph->gridSizeX, ph->gridSizeY, ph->gpuId, maxFound, searchMode, compMode, coinType,
			xpoint, (rKey != 0));
		break;
	default:
		printf("  Invalid search mode format!");
		return;
		break;
	}


	int nbThread = g->GetNbThread();
	Point* p = new Point[nbThread];
	Int* keys = new Int[nbThread];
	std::vector<ITEM> found;

	printf("  GPU          : %s\n", g->deviceName.c_str());

	counters[thId] = 0;

	getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbThread, keys, p);
	ok = g->SetKeys(p);

	ph->hasStarted = true;
	ph->rKeyRequest = false;

	// GPU Thread
	while (ok && !endOfSearch) {

		if (ph->rKeyRequest) {
			getGPUStartingKeys(tRangeStart, tRangeEnd, g->GetGroupSize(), nbThread, keys, p);
			ok = g->SetKeys(p);
			ph->rKeyRequest = false;
		}

		// Call kernel
		switch (searchMode) {
		case (int)SEARCH_MODE_MA:
			ok = g->LaunchSEARCH_MODE_MA(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				if (coinType == COIN_BTC) {
					std::string addr = secp->GetAddress(it.mode, it.hash);
					if (checkPrivKey(addr, keys[it.thId], it.incr, it.mode)) {
						nbFoundKey++;
					}
				}
				else {
					std::string addr = secp->GetAddressETH(it.hash);
					if (checkPrivKeyETH(addr, keys[it.thId], it.incr)) {
						nbFoundKey++;
					}
				}
			}
			break;
		case (int)SEARCH_MODE_MX:
			ok = g->LaunchSEARCH_MODE_MX(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				//Point pk;
				//memcpy((uint32_t*)pk.x.bits, (uint32_t*)it.hash, 8);
				//string addr = secp->GetAddress(it.mode, pk);
				if (checkPrivKeyX(/*addr,*/ keys[it.thId], it.incr, it.mode)) {
					nbFoundKey++;
				}
			}
			break;
		case (int)SEARCH_MODE_SA:
			ok = g->LaunchSEARCH_MODE_SA(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				if (coinType == COIN_BTC) {
					std::string addr = secp->GetAddress(it.mode, it.hash);
					if (checkPrivKey(addr, keys[it.thId], it.incr, it.mode)) {
						nbFoundKey++;
					}
				}
				else {
					std::string addr = secp->GetAddressETH(it.hash);
					if (checkPrivKeyETH(addr, keys[it.thId], it.incr)) {
						nbFoundKey++;
					}
				}
			}
			break;
		case (int)SEARCH_MODE_SX:
			ok = g->LaunchSEARCH_MODE_SX(found, false);
			for (int i = 0; i < (int)found.size() && !endOfSearch; i++) {
				ITEM it = found[i];
				//Point pk;
				//memcpy((uint32_t*)pk.x.bits, (uint32_t*)it.hash, 8);
				//string addr = secp->GetAddress(it.mode, pk);
				if (checkPrivKeyX(/*addr,*/ keys[it.thId], it.incr, it.mode)) {
					nbFoundKey++;
				}
			}
			break;
		default:
			break;
		}

		if (ok) {
			for (int i = 0; i < nbThread; i++) {
				keys[i].Add((uint64_t)STEP_SIZE);
			}
			counters[thId] += (uint64_t)(STEP_SIZE)*nbThread; // Point
		}

	}

	delete[] keys;
	delete[] p;
	delete g;

#else
	ph->hasStarted = true;
	printf("  GPU code not compiled, use -DWITHGPU when compiling.\n");
#endif

	ph->isRunning = false;

}

// ----------------------------------------------------------------------------

bool Rotor::isAlive(TH_PARAM * p)
{

	bool isAlive = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		isAlive = isAlive && p[i].isRunning;

	return isAlive;

}

// ----------------------------------------------------------------------------

bool Rotor::hasStarted(TH_PARAM * p)
{

	bool hasStarted = true;
	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		hasStarted = hasStarted && p[i].hasStarted;

	return hasStarted;

}

// ----------------------------------------------------------------------------

uint64_t Rotor::getGPUCount()
{
	uint64_t count = 0;
	if (value777 > 1000000) {
		count = value777;
	}

	for (int i = 0; i < nbGPUThread; i++)
		count += counters[0x80L + i];
	return count;

}

// ----------------------------------------------------------------------------

uint64_t Rotor::getCPUCount()
{

	uint64_t count = 0;
	for (int i = 0; i < nbCPUThread; i++)
		count += counters[i];
	return count;

}

// ----------------------------------------------------------------------------

void Rotor::rKeyRequest(TH_PARAM * p) {

	int total = nbCPUThread + nbGPUThread;
	for (int i = 0; i < total; i++)
		p[i].rKeyRequest = true;

}
// ----------------------------------------------------------------------------

void Rotor::SetupRanges(uint32_t totalThreads)
{
	Int threads;
	threads.SetInt32(totalThreads);
	rangeDiff.Set(&rangeEnd);
	rangeDiff.Sub(&rangeStart);
	rangeDiff.Div(&threads);
}

// ----------------------------------------------------------------------------

void Rotor::Search(int nbThread, std::vector<int> gpuId, std::vector<int> gridSize, bool& should_exit)
{

	double t0;
	double t1;
	endOfSearch = false;
	nbCPUThread = nbThread;
	nbGPUThread = (useGpu ? (int)gpuId.size() : 0);
	nbFoundKey = 0;

	// setup ranges
	SetupRanges(nbCPUThread + nbGPUThread);

	memset(counters, 0, sizeof(counters));

	if (!useGpu)
		printf("\n");

	TH_PARAM* params = (TH_PARAM*)malloc((nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));
	memset(params, 0, (nbCPUThread + nbGPUThread) * sizeof(TH_PARAM));

	// Launch CPU threads
	for (int i = 0; i < nbCPUThread; i++) {
		params[i].obj = this;
		params[i].threadId = i;
		params[i].isRunning = true;

		params[i].rangeStart.Set(&rangeStart);
		rangeStart.Add(&rangeDiff);
		params[i].rangeEnd.Set(&rangeStart);

#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyCPU, (void*)(params + i), 0, &thread_id);
		ghMutex = CreateMutex(NULL, FALSE, NULL);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyCPU, (void*)(params + i));
		ghMutex = PTHREAD_MUTEX_INITIALIZER;
#endif
	}

	// Launch GPU threads
	for (int i = 0; i < nbGPUThread; i++) {
		params[nbCPUThread + i].obj = this;
		params[nbCPUThread + i].threadId = 0x80L + i;
		params[nbCPUThread + i].isRunning = true;
		params[nbCPUThread + i].gpuId = gpuId[i];
		params[nbCPUThread + i].gridSizeX = gridSize[2 * i];
		params[nbCPUThread + i].gridSizeY = gridSize[2 * i + 1];

		params[nbCPUThread + i].rangeStart.Set(&rangeStart);
		rangeStart.Add(&rangeDiff);
		params[nbCPUThread + i].rangeEnd.Set(&rangeStart);


#ifdef WIN64
		DWORD thread_id;
		CreateThread(NULL, 0, _FindKeyGPU, (void*)(params + (nbCPUThread + i)), 0, &thread_id);
#else
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, &_FindKeyGPU, (void*)(params + (nbCPUThread + i)));
#endif
	}

#ifndef WIN64
	setvbuf(stdout, NULL, _IONBF, 0);
#endif
	printf("\n");

	uint64_t lastCount = 0;
	uint64_t gpuCount = 0;
	uint64_t lastGPUCount = 0;

	// Key rate smoothing filter
#define FILTER_SIZE 8
	double lastkeyRate[FILTER_SIZE];
	double lastGpukeyRate[FILTER_SIZE];
	uint32_t filterPos = 0;

	double keyRate = 0.0;
	double gpuKeyRate = 0.0;
	char timeStr[256];

	memset(lastkeyRate, 0, sizeof(lastkeyRate));
	memset(lastGpukeyRate, 0, sizeof(lastkeyRate));

	// Wait that all threads have started
	while (!hasStarted(params)) {
		Timer::SleepMillis(500);
	}

	// Reset timer
	Timer::Init();
	t0 = Timer::get_tick();
	startTime = t0;
	Int p100;
	Int ICount;
	p100.SetInt32(100);
	double completedPerc = 0;
	uint64_t rKeyCount = 0;
	while (isAlive(params)) {

		int delay = 1000;
		while (isAlive(params) && delay > 0) {
			Timer::SleepMillis(500);
			delay -= 500;
		}

		gpuCount = getGPUCount();
		uint64_t count = getCPUCount() + gpuCount;
		ICount.SetInt64(count);
		int completedBits = ICount.GetBitLength();
		if (rKey <= 0) {
			completedPerc = CalcPercantage(ICount, rangeStart, rangeDiff2);
			//ICount.Mult(&p100);
			//ICount.Div(&this->rangeDiff2);
			//completedPerc = std::stoi(ICount.GetBase10());
		}
		minuty++;

		if (next > 0) {
			if (rKey < 1) {
				if (minuty > next * 55) {

					char* ctimeBuff;
					time_t now = time(NULL);
					ctimeBuff = ctime(&now);
					FILE* ptrFile = fopen("Rotor-Cuda_Continue.bat", "w+");
					fprintf(ptrFile, ":loop \n");
					fprintf(ptrFile, "%s\n", stroka.c_str());
					fprintf(ptrFile, "goto :loop \n");
					fprintf(ptrFile, "created: %s", ctimeBuff);
					fprintf(ptrFile, "%" PRIu64 "\n", count);
					fprintf(ptrFile, "To continue correctly, DO NOT change the parameters in this file! \n");
					fprintf(ptrFile, "If you no longer need the continuation, DELETE this file! \n");
					fclose(ptrFile);
					minuty = 0;
				}
			}
		}

		t1 = Timer::get_tick();
		keyRate = (double)(count - lastCount) / (t1 - t0);
		gpuKeyRate = (double)(gpuCount - lastGPUCount) / (t1 - t0);
		lastkeyRate[filterPos % FILTER_SIZE] = keyRate;
		lastGpukeyRate[filterPos % FILTER_SIZE] = gpuKeyRate;
		filterPos++;

		// KeyRate smoothing
		double avgKeyRate = 0.0;
		double avgGpuKeyRate = 0.0;
		uint32_t nbSample;
		for (nbSample = 0; (nbSample < FILTER_SIZE) && (nbSample < filterPos); nbSample++) {
			avgKeyRate += lastkeyRate[nbSample];
			avgGpuKeyRate += lastGpukeyRate[nbSample];
		}
		avgKeyRate /= (double)(nbSample);
		avgGpuKeyRate /= (double)(nbSample);

		zhdat++;

		unsigned long long int years88, days88, hours88, minutes88, seconds88;

		if (nbit2 > 0) {
			
			if (rKey < 1) {

				if (value777 > 1000000) {

					if (zhdat > 10) {
						double avgKeyRate2 = avgKeyRate * 1;
						rhex.Add(avgKeyRate2);
						double avgKeyRate5 = avgKeyRate * 1;
						unsigned long long int input88;
						unsigned long long int input55;
						unsigned long long int minnn;
						string streek77 = rangeDiffbar.GetBase10().c_str();
						std::istringstream iss(streek77);
						iss >> input55;
						minnn = input55 - count;
						input88 = minnn / avgKeyRate5;
						years88 = input88 / 60 / 60 / 24 / 365;
						days88 = (input88 / 60 / 60 / 24) % 365;
						hours88 = (input88 / 60 / 60) % 24;
						minutes88 = (input88 / 60) % 60;
						seconds88 = input88 % 60;
					}
				}
				else {
					double avgKeyRate2 = avgKeyRate * 1;
					rhex.Add(avgKeyRate2);
					double avgKeyRate5 = avgKeyRate * 1;
					unsigned long long int input88;
					unsigned long long int input55;
					unsigned long long int minnn;
					string streek77 = rangeDiffbar.GetBase10().c_str();
					std::istringstream iss(streek77);
					iss >> input55;
					minnn = input55 - count;
					input88 = minnn / avgKeyRate5;
					years88 = input88 / 60 / 60 / 24 / 365;
					days88 = (input88 / 60 / 60 / 24) % 365;
					hours88 = (input88 / 60 / 60) % 24;
					minutes88 = (input88 / 60) % 60;
					seconds88 = input88 % 60;
				}
			}
			else {

				double avgKeyRate2 = avgKeyRate * 1;
				double avgKeyRate3 = avgKeyRate2 / nbit2;
				rhex.Add(avgKeyRate3);

			}
		}
		else {

			if (rKey < 1) {

				if (value777 > 1000000) {

					if (zhdat > 10) {
						double avgKeyRate2 = avgKeyRate * 1;
						rhex.Add(avgKeyRate2);
						double avgKeyRate5 = avgKeyRate * 1;
						unsigned long long int input88;
						unsigned long long int input55;
						unsigned long long int minnn;
						string streek77 = rangeDiffbar.GetBase10().c_str();
						std::istringstream iss(streek77);
						iss >> input55;
						minnn = input55 - count;
						input88 = minnn / avgKeyRate5;
						years88 = input88 / 60 / 60 / 24 / 365;
						days88 = (input88 / 60 / 60 / 24) % 365;
						hours88 = (input88 / 60 / 60) % 24;
						minutes88 = (input88 / 60) % 60;
						seconds88 = input88 % 60;
					}
				}
				else {
					double avgKeyRate2 = avgKeyRate * 1;
					rhex.Add(avgKeyRate2);
					double avgKeyRate5 = avgKeyRate * 1;
					unsigned long long int input88;
					unsigned long long int input55;
					unsigned long long int minnn;
					string streek77 = rangeDiffbar.GetBase10().c_str();
					std::istringstream iss(streek77);
					iss >> input55;
					minnn = input55 - count;
					input88 = minnn / avgKeyRate5;
					years88 = input88 / 60 / 60 / 24 / 365;
					days88 = (input88 / 60 / 60 / 24) % 365;
					hours88 = (input88 / 60 / 60) % 24;
					minutes88 = (input88 / 60) % 60;
					seconds88 = input88 % 60;
				}
			}
			else {

				double avgKeyRate2 = avgKeyRate * 1;
				double avgKeyRate3 = avgKeyRate2 / gpucores;
				rhex.Add(avgKeyRate3);

			}
		}
		
		if (years88 > 300) {

			if (display > 0) {

				if (years88 > 0) {

					if (nbit2 < 1) {

						if (rKey > 0) {

							if (isAlive(params)) {

								if (avgGpuKeyRate > 1000000000) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Gk/s] [T: %s]   ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										rhex.GetBase16().c_str(),
										nbFoundKey,
										avgGpuKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
								else {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Mk/s] [T: %s]   ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										rhex.GetBase16().c_str(),
										nbFoundKey,
										avgGpuKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
						else {

							string skoka = "";
							if (avgGpuKeyRate > 1000000000) {

								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rhex.GetBase16().c_str(),
										nbFoundKey,
										completedPerc,
										avgGpuKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
							}
							else {

								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rhex.GetBase16().c_str(),
										nbFoundKey,
										completedPerc,
										avgGpuKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
					}
					else {

						if (rKey > 0) {
							if (isAlive(params)) {

								if (avgGpuKeyRate > 1000000000) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										rhex.GetBase16().c_str(),
										nbFoundKey,
										nbit2,
										avgKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
								else {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										rhex.GetBase16().c_str(),
										nbFoundKey,
										nbit2,
										avgKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
						else {

							if (avgGpuKeyRate > 1000000000) {
								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rhex.GetBase16().c_str(),
										nbFoundKey,
										completedPerc,
										nbit2,
										avgKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
							}
							else {
								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rhex.GetBase16().c_str(),
										nbFoundKey,
										completedPerc,
										nbit2,
										avgKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
					}
				}
				else {

					if (days88 > 0) {

						if (nbit2 < 1) {

							if (rKey > 0) {

								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								string skoka = "";
								if (avgGpuKeyRate > 1000000000) {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											completedPerc,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											completedPerc,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
						else {

							if (rKey > 0) {
								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								if (avgGpuKeyRate > 1000000000) {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
					}
					else {
						if (nbit2 < 1) {

							if (rKey > 0) {

								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								string skoka = "";
								if (avgGpuKeyRate > 1000000000) {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											completedPerc,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
						else {

							if (rKey > 0) {
								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								if (avgGpuKeyRate > 1000000000) {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
					}
				}
			}
			else {

				if (years88 > 0) {

					if (nbit2 < 1) {

						if (rKey > 0) {

							if (isAlive(params)) {

								if (avgGpuKeyRate > 1000000000) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Gk/s] [T: %s]    ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										nbFoundKey,
										avgGpuKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
								else {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Mk/s] [T: %s]    ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										nbFoundKey,
										avgGpuKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
						else {

							string skoka = "";
							if (avgGpuKeyRate > 1000000000) {

								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [F: %d] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										nbFoundKey,
										completedPerc,
										avgGpuKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
							}
							else {

								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [F: %d] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										nbFoundKey,
										completedPerc,
										avgGpuKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
					}
					else {

						if (rKey > 0) {
							if (isAlive(params)) {

								if (avgGpuKeyRate > 1000000000) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]   ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										nbFoundKey,
										nbit2,
										avgKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
								else {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]   ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										nbFoundKey,
										nbit2,
										avgKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
						else {

							if (avgGpuKeyRate > 1000000000) {
								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										nbFoundKey,
										completedPerc,
										nbit2,
										avgKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
							}
							else {
								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										nbFoundKey,
										completedPerc,
										nbit2,
										avgKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
					}
				}
				else {

					if (days88 > 0) {

						if (nbit2 < 1) {

							if (rKey > 0) {

								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Gk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Mk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								string skoka = "";
								if (avgGpuKeyRate > 1000000000) {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											completedPerc,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											completedPerc,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
						else {

							if (rKey > 0) {
								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								if (avgGpuKeyRate > 1000000000) {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
					}
					else {
						if (nbit2 < 1) {

							if (rKey > 0) {

								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Gk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Mk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								string skoka = "";
								if (avgGpuKeyRate > 1000000000) {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											completedPerc,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											completedPerc,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
						else {

							if (rKey > 0) {
								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								if (avgGpuKeyRate > 1000000000) {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
					}
				}
			}

		}
		else {
			if (display > 0) {

				if (years88 > 0) {

					if (nbit2 < 1) {

						if (rKey > 0) {

							if (isAlive(params)) {

								if (avgGpuKeyRate > 1000000000) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Gk/s] [T: %s]   ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										rhex.GetBase16().c_str(),
										nbFoundKey,
										avgGpuKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
								else {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Mk/s] [T: %s]   ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										rhex.GetBase16().c_str(),
										nbFoundKey,
										avgGpuKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
						else {

							string skoka = "";
							if (avgGpuKeyRate > 1000000000) {

								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [%s] [F: %d] [Y:%03llu D:%03llu] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rhex.GetBase16().c_str(),
										nbFoundKey,
										years88,
										days88,
										completedPerc,
										avgGpuKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
							}
							else {

								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [%s] [F: %d] [Y:%03llu D:%03llu] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rhex.GetBase16().c_str(),
										nbFoundKey,
										years88,
										days88,
										completedPerc,
										avgGpuKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
					}
					else {

						if (rKey > 0) {
							if (isAlive(params)) {

								if (avgGpuKeyRate > 1000000000) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										rhex.GetBase16().c_str(),
										nbFoundKey,
										nbit2,
										avgKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
								else {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										rhex.GetBase16().c_str(),
										nbFoundKey,
										nbit2,
										avgKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
						else {

							if (avgGpuKeyRate > 1000000000) {
								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [%s] [F: %d] [Y:%03llu D:%03llu] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rhex.GetBase16().c_str(),
										nbFoundKey,
										years88,
										days88,
										completedPerc,
										nbit2,
										avgKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
							}
							else {
								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [%s] [F: %d] [Y:%03llu D:%03llu] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										rhex.GetBase16().c_str(),
										nbFoundKey,
										years88,
										days88,
										completedPerc,
										nbit2,
										avgKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
					}
				}
				else {

					if (days88 > 0) {

						if (nbit2 < 1) {

							if (rKey > 0) {

								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								string skoka = "";
								if (avgGpuKeyRate > 1000000000) {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [D:%03llu %02llu:%02llu:%02llu] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											days88,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [D:%03llu %02llu:%02llu:%02llu] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											days88,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
						else {

							if (rKey > 0) {
								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								if (avgGpuKeyRate > 1000000000) {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [D:%03llu %02llu:%02llu:%02llu] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											days88,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [D:%03llu %02llu:%02llu:%02llu] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											days88,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
					}
					else {
						if (nbit2 < 1) {

							if (rKey > 0) {

								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [GPU: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								string skoka = "";
								if (avgGpuKeyRate > 1000000000) {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [%02llu:%02llu:%02llu] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [%02llu:%02llu:%02llu] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
						else {

							if (rKey > 0) {
								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [%s] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											rhex.GetBase16().c_str(),
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								if (avgGpuKeyRate > 1000000000) {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [%02llu:%02llu:%02llu] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [%s] [F: %d] [%02llu:%02llu:%02llu] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											rhex.GetBase16().c_str(),
											nbFoundKey,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
					}
				}
			}
			else {

				if (years88 > 0) {

					if (nbit2 < 1) {

						if (rKey > 0) {

							if (isAlive(params)) {

								if (avgGpuKeyRate > 1000000000) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Gk/s] [T: %s]    ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										nbFoundKey,
										avgGpuKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
								else {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Mk/s] [T: %s]    ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										nbFoundKey,
										avgGpuKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
						else {

							string skoka = "";
							if (avgGpuKeyRate > 1000000000) {

								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [F: %d] [Y:%03llu D:%03llu] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										nbFoundKey,
										years88,
										days88,
										completedPerc,
										avgGpuKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
							}
							else {

								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [F: %d] [Y:%03llu D:%03llu] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										nbFoundKey,
										years88,
										days88,
										completedPerc,
										avgGpuKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
					}
					else {

						if (rKey > 0) {
							if (isAlive(params)) {

								if (avgGpuKeyRate > 1000000000) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]   ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										nbFoundKey,
										nbit2,
										avgKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
								else {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]   ",
										toTimeStr(t1, timeStr),
										rKeyCount,
										nbFoundKey,
										nbit2,
										avgKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
						else {

							if (avgGpuKeyRate > 1000000000) {
								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [F: %d] [Y:%03llu D:%03llu] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										nbFoundKey,
										years88,
										days88,
										completedPerc,
										nbit2,
										avgKeyRate / 1000000000.0,
										formatThousands(count).c_str());
								}
							}
							else {
								if (isAlive(params)) {
									memset(timeStr, '\0', 256);
									printf("\r  [%s] [F: %d] [Y:%03llu D:%03llu] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]  ",
										toTimeStr(t1, timeStr),
										nbFoundKey,
										years88,
										days88,
										completedPerc,
										nbit2,
										avgKeyRate / 1000000.0,
										formatThousands(count).c_str());
								}
							}
						}
					}
				}
				else {

					if (days88 > 0) {

						if (nbit2 < 1) {

							if (rKey > 0) {

								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Gk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Mk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								string skoka = "";
								if (avgGpuKeyRate > 1000000000) {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [D:%03llu %02llu:%02llu:%02llu] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											days88,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [D:%03llu %02llu:%02llu:%02llu] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											days88,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
						else {

							if (rKey > 0) {
								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								if (avgGpuKeyRate > 1000000000) {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [D:%03llu %02llu:%02llu:%02llu] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											days88,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [D:%03llu %02llu:%02llu:%02llu] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											days88,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
					}
					else {
						if (nbit2 < 1) {

							if (rKey > 0) {

								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Gk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [GPU: %.2f Mk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								string skoka = "";
								if (avgGpuKeyRate > 1000000000) {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [%02llu:%02llu:%02llu] [C: %lf %%] [GPU: %.2f Gk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											avgGpuKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {

									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [%02llu:%02llu:%02llu] [C: %lf %%] [GPU: %.2f Mk/s] [T: %s]   ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											avgGpuKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
						else {

							if (rKey > 0) {
								if (isAlive(params)) {

									if (avgGpuKeyRate > 1000000000) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Gk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
									else {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [R: %llu] [F: %d] [CPU %d: %.2f Mk/s] [T: %s]    ",
											toTimeStr(t1, timeStr),
											rKeyCount,
											nbFoundKey,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
							else {

								if (avgGpuKeyRate > 1000000000) {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [%02llu:%02llu:%02llu] [C: %lf %%] [CPU %d: %.2f Gk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000000.0,
											formatThousands(count).c_str());
									}
								}
								else {
									if (isAlive(params)) {
										memset(timeStr, '\0', 256);
										printf("\r  [%s] [F: %d] [%02llu:%02llu:%02llu] [C: %lf %%] [CPU %d: %.2f Mk/s] [T: %s]  ",
											toTimeStr(t1, timeStr),
											nbFoundKey,
											hours88,
											minutes88,
											seconds88,
											completedPerc,
											nbit2,
											avgKeyRate / 1000000.0,
											formatThousands(count).c_str());
									}
								}
							}
						}
					}
				}
			}
		}
		
		if (rKey > 0) {
			if ((count - lastrKey) > (1000000000 * rKey)) {
				// rKey request
				rKeyRequest(params);
				lastrKey = count;
				rKeyCount++;
				rKeyCount2 += rKeyCount;
			}
		}

		lastCount = count;
		lastGPUCount = gpuCount;
		t0 = t1;
		if (should_exit || nbFoundKey >= targetCounter || completedPerc > 100.5)
			endOfSearch = true;
	}

	free(params);

	}

// ----------------------------------------------------------------------------

std::string Rotor::GetHex(std::vector<unsigned char> &buffer)
{
	std::string ret;

	char tmp[128];
	for (int i = 0; i < (int)buffer.size(); i++) {
		sprintf(tmp, "%02X", buffer[i]);
		ret.append(tmp);
	}
	return ret;
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

int Rotor::CheckBloomBinary(const uint8_t * _xx, uint32_t K_LENGTH)
{
	if (bloom->check(_xx, K_LENGTH) > 0) {
		uint8_t* temp_read;
		uint64_t half, min, max, current; //, current_offset
		int64_t rcmp;
		int32_t r = 0;
		min = 0;
		current = 0;
		max = TOTAL_COUNT;
		half = TOTAL_COUNT;
		while (!r && half >= 1) {
			half = (max - min) / 2;
			temp_read = DATA + ((current + half) * K_LENGTH);
			rcmp = memcmp(_xx, temp_read, K_LENGTH);
			if (rcmp == 0) {
				r = 1;  //Found!!
			}
			else {
				if (rcmp < 0) { //data < temp_read
					max = (max - half);
				}
				else { // data > temp_read
					min = (min + half);
				}
				current = min;
			}
		}
		return r;
	}
	return 0;
}

// ----------------------------------------------------------------------------

bool Rotor::MatchHash(uint32_t * _h)
{
	if (_h[0] == hash160Keccak[0] &&
		_h[1] == hash160Keccak[1] &&
		_h[2] == hash160Keccak[2] &&
		_h[3] == hash160Keccak[3] &&
		_h[4] == hash160Keccak[4]) {
		return true;
	}
	else {
		return false;
	}
}

// ----------------------------------------------------------------------------

bool Rotor::MatchXPoint(uint32_t * _h)
{
	if (_h[0] == xpoint[0] &&
		_h[1] == xpoint[1] &&
		_h[2] == xpoint[2] &&
		_h[3] == xpoint[3] &&
		_h[4] == xpoint[4] &&
		_h[5] == xpoint[5] &&
		_h[6] == xpoint[6] &&
		_h[7] == xpoint[7]) {
		return true;
	}
	else {
		return false;
	}
}

// ----------------------------------------------------------------------------

std::string Rotor::formatThousands(uint64_t x)
{
	char buf[32] = "";

	sprintf(buf, "%llu", x);

	std::string s(buf);

	int len = (int)s.length();

	int numCommas = (len - 1) / 3;

	if (numCommas == 0) {
		return s;
	}

	std::string result = "";

	int count = ((len % 3) == 0) ? 0 : (3 - (len % 3));

	for (int i = 0; i < len; i++) {
		result += s[i];

		if (count++ == 2 && i < len - 1) {
			result += ",";
			count = 0;
		}
	}
	return result;
}


// ----------------------------------------------------------------------------

char* Rotor::toTimeStr(int sec, char* timeStr)
{
	int h, m, s;
	h = (sec / 3600);
	m = (sec - (3600 * h)) / 60;
	s = (sec - (3600 * h) - (m * 60));
	sprintf(timeStr, "%0*d:%0*d:%0*d", 2, h, 2, m, 2, s);
	return (char*)timeStr;
}

// ----------------------------------------------------------------------------

//#include <gmp.h>
//#include <gmpxx.h>
// ((input - min) * 100) / (max - min)
//double Rotor::GetPercantage(uint64_t v)
//{
//	//Int val(v);
//	//mpz_class x(val.GetBase16().c_str(), 16);
//	//mpz_class r(rangeStart.GetBase16().c_str(), 16);
//	//x = x - mpz_class(rangeEnd.GetBase16().c_str(), 16);
//	//x = x * 100;
//	//mpf_class y(x);
//	//y = y / mpf_class(r);
//	return 0;// y.get_d();
//}
