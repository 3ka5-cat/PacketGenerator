#include "common.h"

std::string glblError = "";

void setGlobalError(std::string err)
{
	glblError = err;
}

const std::string& getGlobalError(void)
{
	return glblError;
}
