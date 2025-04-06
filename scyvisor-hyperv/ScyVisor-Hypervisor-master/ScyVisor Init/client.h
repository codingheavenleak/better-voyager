#pragma once

#include <string>

namespace Client {

	bool driverExists(const std::wstring& driverPath);
	void writeDriver(const std::vector<unsigned char>& driverData, const std::wstring& outputPath);
	void loadDriver(const std::string& host, const std::string& port);

}
