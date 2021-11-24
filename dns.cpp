#include <map>
#include <set>
#include <list>
#include <cmath>
#include <ctime>
#include <deque>
#include <queue>
#include <stack>
#include <string>
#include <bitset>
#include <cstdio>
#include <limits>
#include <vector>
#include <climits>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <numeric>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <unordered_map>

using namespace std;
int Q_count, A_count;
std::string domain;
int domain_len;

const char *hex_char_to_bin(char c)
{
    switch (toupper(c))
    {
    case '0':
        return "0000";
    case '1':
        return "0001";
    case '2':
        return "0010";
    case '3':
        return "0011";
    case '4':
        return "0100";
    case '5':
        return "0101";
    case '6':
        return "0110";
    case '7':
        return "0111";
    case '8':
        return "1000";
    case '9':
        return "1001";
    case 'A':
        return "1010";
    case 'B':
        return "1011";
    case 'C':
        return "1100";
    case 'D':
        return "1101";
    case 'E':
        return "1110";
    case 'F':
        return "1111";
    }
    return "";
}

const char *qtype(int n)
{
    switch (n)
    {
    case 1:
        return "A";
    case 2:
        return "NS";
    case 5:
        return "CNAME";
    case 6:
        return "SOA";
    case 12:
        return "PTR";
    case 15:
        return "MX";
    case 16:
        return "TXT";
    case 28:
        return "AAAA";
    case 33:
        return "SRV";
    case 35:
        return "NAPTR";
    case 38:
        return "A6";
    }
    return "";
}

const char *qclass(int n)
{
    switch (n)
    {
    case 1:
        return "IN";
    case 3:
        return "CH";
    case 4:
        return "HS";
    case 255:
        return "ANY";
    }
    return "";
}

std::string hex_str_to_bin_str(const std::string &hex)
{
    std::string bin;
    for (unsigned i = 0; i != hex.length(); ++i)
        bin += hex_char_to_bin(hex[i]);
    return bin;
}

void processHeaderLine(const std::string &line)
{
    std::string id = line.substr(0, 16);
    char *c;
    cout << strtoull(id.c_str(), &c, 2) << endl;
    cout << ";; flags:";
    if (line[16] == '1')
        cout << " qr";

    if (line[21] == '1')
        cout << " aa";

    if (line[22] == '1')
        cout << " tc";

    if (line[23] == '1')
        cout << " rd";

    if (line[24] == '1')
        cout << " ra";

    cout << "; QUERY: ";
    std::string query = line.substr(32, 16);
    Q_count = strtoull(query.c_str(), &c, 2);
    cout << Q_count;

    cout << ", ANSWER: ";
    std::string answer = line.substr(48, 16);
    A_count = strtoull(answer.c_str(), &c, 2);
    cout << A_count;

    cout << ", AUTHORITY: ";
    std::string auth = line.substr(64, 16);
    cout << strtoull(auth.c_str(), &c, 2);

    cout << ", ADDITIONAL: ";
    std::string add = line.substr(80, 16);
    cout << strtoull(add.c_str(), &c, 2);
    cout << endl;
}

int processQLine(const std::string &line)
{
    cout << ";";
    char *c;
    int total = 0;
    int length = 0;
    do
    {
        std::string length_str = line.substr(total, 8);
        length = strtoull(length_str.c_str(), &c, 2);
        total += 8;
        for (int i = 0; i < length; ++i)
        {
            std::string name = line.substr(total, 8);
            char letter = (char)strtoull(name.c_str(), &c, 2);
            cout << letter;
            domain += letter;
            total += 8;
        }
        if (length)
        {
            cout << ".";
            domain += ".";
        }

    } while (length != 0);
    cout << "\t\t";

    std::string qType = line.substr(total, 16);
    std::string qClass = line.substr(total + 16, 16);
    cout << qclass(strtoull(qClass.c_str(), &c, 2)) << "\t";
    cout << qtype(strtoull(qType.c_str(), &c, 2));

    return total + 32;
}

int processALine(const std::string &line)
{
    cout << domain;
    char *c;
    int total = domain.size() * 8;

    if (domain.size() > domain_len + 8 && domain_len != 0)
    {
        cout << "\t";
    }
    else
    {
        cout << "\t\t";
    }

    std::string qType = line.substr(16, 16);
    std::string qClass = line.substr(32, 16);
    std::string ttl = line.substr(48, 32);
    cout << strtoull(ttl.c_str(), &c, 2) << "\t";
    cout << qclass(strtoull(qClass.c_str(), &c, 2)) << "\t";
    const char *qtype_arr = qtype(strtoull(qType.c_str(), &c, 2));
    cout << qtype_arr << "\t";

    total = 96;

    if (!strcmp(qtype_arr, "A"))
    {
        for (int i = 0; i < 4; ++i)
        {
            std::string ip = line.substr(total, 8);
            cout << strtoull(ip.c_str(), &c, 2);
            total += 8;
            if (i != 3)
                cout << ".";
        }
    }
    else if (!strcmp(qtype_arr, "AAAA"))
    {
        bool first = true;
        for (int i = 0; i < 8; ++i)
        {
            std::string ip = line.substr(total, 16);
            int decimal_value = strtoull(ip.c_str(), &c, 2);

            std::stringstream ss;
            ss << std::hex << decimal_value;
            std::string res(ss.str());

            total += 16;
            if (decimal_value == 0)
            {
                if (first)
                {
                    cout << ":";
                    first = false;
                }
                continue;
            }
            else
            {
                first = true;
            }
            std::cout << res;
            if (i != 7)
                cout << ":";
        }
    }
    else if (!strcmp(qtype_arr, "CNAME"))
    {
        domain_len = domain.size();
        size_t pos = domain.find(".");
        domain.erase(0, pos);
        std::string cname_size = line.substr(total - 16, 16);
        std::string cname_start;

        int cname_lenght = strtoull(cname_size.c_str(), &c, 2);

        for (int i = 0; i < cname_lenght - pos; ++i)
        {
            std::string cname = line.substr(total + 8, 8);
            char letter = (char)strtoull(cname.c_str(), &c, 2);
            if (letter == '\t')
            {
                cname_start += ".";
            }
            else
            {
                cname_start += letter;
            }
            total += 8;
        }
        total += 8 * pos;
        domain = cname_start + domain;
        cout << domain;
    }
    return total;
}

int main()
{
    /* Enter your code here. Read input from STDIN. Print output to STDOUT */

    cout << ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ";
    int op_count = 0;
    bool is_q_header = true;
    bool is_a_header = true;
    std::string buffer;
    for (std::string line; std::getline(std::cin, line);)
    {
        int index;

        if (line.size() == 68)
        {
            index = 2;
        }
        else
        {
            index = 1;
        }
        line.erase(std::remove(line.begin(), line.end(), '\\'), line.end());
        line.erase(std::remove(line.begin(), line.end(), 'x'), line.end());

        std::stringstream ss;
        line = hex_str_to_bin_str(line.substr(0, line.size() - index));

        buffer += line;
    }

    while (true)
    {
        op_count++;
        if (op_count == 1)
        {
            processHeaderLine(buffer);
            buffer.erase(0, 96);
        }
        else
        {
            if (Q_count > 0)
            {
                Q_count--;
                if (is_q_header)
                {
                    cout << ";; QUESTION SECTION:" << endl;
                    is_q_header = false;
                }

                int qsize = processQLine(buffer);
                buffer.erase(0, qsize);
            }
            else if (A_count > 0)
            {
                A_count--;
                if (is_a_header)
                {
                    cout << endl;
                    cout << ";; ANSWER SECTION:" << endl;
                    is_a_header = false;
                }
                // cout << buffer;
                int asize = processALine(buffer);
                buffer.erase(0, asize);
            }
            else
            {
                break;
            }
        }
        cout << endl;
    }
    return 0;
}
