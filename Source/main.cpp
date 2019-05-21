#include <iostream>
#include "CAIOS.hpp"

int main() {
	string message;
	cout << "Tweet > "; getline(cin, message);
	CAIOS::Twitter::tweet(message);
	return 0;
}