#include <iostream>
#include <string>
#include <fstream>

#include <Windows.h>

#include "Master.h"

using namespace std;

int main() {
	Master::Process pmaster("calc.exe");
	HANDLE kakao = pmaster.getHandle();
	if (kakao == INVALID_HANDLE_VALUE) {
		cout << "shit!" << endl;
	}

	pmaster.Dump2PE("calc.dmp", (void *)0x00400000);

	int v;
	cin >> v;

	return 0;
}