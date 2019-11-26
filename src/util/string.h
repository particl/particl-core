// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_STRING_H
#define BITCOIN_UTIL_STRING_H

#include <string>
#include <vector>

/**
 * Join a list of items
 *
 * @param list       The list to join
 * @param separator  The separator
 * @param unary_op   Apply this operator to each item in the list
 */
template <typename T, typename UnaryOp>
std::string Join(const std::vector<T>& list, const std::string& separator, UnaryOp unary_op)
{
    std::string ret;
    for (size_t i = 0; i < list.size(); ++i) {
        if (i > 0) ret += separator;
        ret += unary_op(list.at(i));
    }
    return ret;
}

inline std::string Join(const std::vector<std::string>& list, const std::string& separator)
{
    return Join(list, separator, [](const std::string& i) { return i; });
}

namespace part
{
    void *memrchr(const void *s, int c, size_t n);

    int memcmp_nta(const void *cs, const void *ct, size_t count);

    void ReplaceStrInPlace(std::string &subject, const std::string search, const std::string replace);
    bool IsStringBoolPositive(const std::string &value);
    bool IsStringBoolNegative(const std::string &value);
    bool GetStringBool(const std::string &value, bool &fOut);
    bool IsStrOnlyDigits(const std::string &s);
    std::string BytesReadable(uint64_t nBytes);
    bool stringsMatchI(const std::string &sString, const std::string &sFind, int type);
    std::string StripQuotes(std::string s);
    std::string &TrimQuotes(std::string &s);
    std::string &LTrimWhitespace(std::string &s);
    std::string &RTrimWhitespace(std::string &s);
    std::string &TrimWhitespace(std::string &s);
    int64_t strToEpoch(const char *input, bool fFillMax=false);
    bool endsWith(const std::string &str, const std::string &suffix);
}

#endif // BITCOIN_UTIL_STRENCODINGS_H
