#ifndef __STRINGUTILS_H_
#define __STRINGUTILS_H_

#include <string>
#include <vector>

using namespace std;

class StringUtils
{

public:

    static int SplitString(const string& input, 
        const string& delimiter, vector<string>& results, 
        bool includeEmpties = true);

};

#endif
