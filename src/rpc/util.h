// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_UTIL_H
#define BITCOIN_RPC_UTIL_H

#include <pubkey.h>
#include <script/standard.h>
#include <univalue.h>

#include <boost/variant/static_visitor.hpp>

#include <string>
#include <vector>

class CKeyStore;
class CPubKey;
class CScript;

CPubKey HexToPubKey(const std::string& hex_in);
CPubKey AddrToPubKey(CKeyStore* const keystore, const std::string& addr_in);
CScript CreateMultisigRedeemscript(const int m_required, const std::vector<CPubKey>& pubkeys);

UniValue DescribeAddress(const CTxDestination& dest);

class RPCHelpUniValue : public UniValue
{
public:
    RPCHelpUniValue(UniValue::VType initialType, const std::string& initialStr = "", const std::string& m_help = "", bool m_required = false) {
        typ = initialType;
        val = initialStr;
        help = m_help;
        required = m_required;
    }
    RPCHelpUniValue(uint64_t val_, const std::string& m_help = "", bool m_required = false) {
        setInt(val_);
        help = m_help;
        required = m_required;
    }
    RPCHelpUniValue(int64_t val_, const std::string& m_help = "", bool m_required = false) {
        setInt(val_);
        help = m_help;
        required = m_required;
    }
    RPCHelpUniValue(bool val_, const std::string& m_help = "", bool m_required = false) {
        setBool(val_);
        help = m_help;
        required = m_required;
    }
    RPCHelpUniValue(int val_, const std::string& m_help = "", bool m_required = false) {
        setInt(val_);
        help = m_help;
        required = m_required;
    }
    RPCHelpUniValue(double val_, const std::string& m_help = "", bool m_required = false) {
        setFloat(val_);
        help = m_help;
        required = m_required;
    }
    RPCHelpUniValue(const std::string& val_, const std::string& m_help = "", bool m_required = false) {
        setStr(val_);
        help = m_help;
        required = m_required;
    }
    RPCHelpUniValue(const char *val_, const std::string& m_help = "", bool m_required = false) {
        std::string s(val_);
        setStr(s);
        help = m_help;
        required = m_required;
    }
    ~RPCHelpUniValue() {}

    void clear();


    bool push_back(const RPCHelpUniValue& val);
    bool push_back(const std::string& val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal(VSTR, val_, m_help, m_required);
        return push_back(tmpVal);
    }
    bool push_back(const char *val_, const std::string& m_help = "", bool m_required = false) {
        std::string s(val_);
        return push_back(s);
    }
    bool push_back(uint64_t val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal(val_, m_help, m_required);
        return push_back(tmpVal);
    }
    bool push_back(int64_t val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal(val_, m_help, m_required);
        return push_back(tmpVal);
    }
    bool push_back(int val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal(val_, m_help, m_required);
        return push_back(tmpVal);
    }
    bool push_back(double val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal(val_, m_help, m_required);
        return push_back(tmpVal);
    }
    bool push_backV(const std::vector<RPCHelpUniValue>& vec);

    void __pushKV(const std::string& key, const RPCHelpUniValue& val, const std::string& m_help = "", bool m_required = false);
    bool pushKV(const std::string& key, const RPCHelpUniValue& val, const std::string& m_help = "", bool m_required = false);
    bool pushKV(const std::string& key, const std::string& val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal(VSTR, val_, m_help, m_required);
        return pushKV(key, tmpVal);
    }
    bool pushKV(const std::string& key, const char *val_, const std::string& m_help = "", bool m_required = false) {
        std::string _val(val_);
        return pushKV(key, _val, m_help, m_required);
    }
    bool pushKV(const std::string& key, int64_t val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal(val_, m_help, m_required);
        return pushKV(key, tmpVal);
    }
    bool pushKV(const std::string& key, uint64_t val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal(val_, m_help, m_required);
        return pushKV(key, tmpVal);
    }
    bool pushKV(const std::string& key, bool val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal((bool)val_, m_help, m_required);
        return pushKV(key, tmpVal);
    }
    bool pushKV(const std::string& key, int val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal((int64_t)val_, m_help, m_required);
        return pushKV(key, tmpVal);
    }
    bool pushKV(const std::string& key, double val_, const std::string& m_help = "", bool m_required = false) {
        RPCHelpUniValue tmpVal(val_, m_help, m_required);
        return pushKV(key, tmpVal);
    }
    bool pushKVs(const RPCHelpUniValue& obj);

    std::string write(unsigned int prettyIndent = 0, unsigned int indentLevel = 0) const;
    std::string WriteUniv(unsigned int prettyIndent = 0, unsigned int indentLevel = 0) const;

private:
    UniValue::VType typ;
    std::string val;                       // numbers are stored as C++ strings
    std::vector<std::string> keys;
    std::string help;
    std::vector<std::string> helps;
    bool required;
    std::vector<bool> requireds;
    std::vector<RPCHelpUniValue> values;

    bool findKey(const std::string& key, size_t& retIdx) const;
    void GetLeft(unsigned int pretty_indent, unsigned int indent_level, std::vector<std::string>& out) const;
    void GetRight(std::vector<std::string>& out) const;
    void GetArrayLeft(unsigned int pretty_indent, unsigned int indent_level, std::vector<std::string>& out) const;
    void GetArrayRight(std::vector<std::string>& out) const;
    void GetObjectLeft(unsigned int pretty_indent, unsigned int indent_level, std::vector<std::string>& out) const;
    void GetObjectRight(std::vector<std::string>& out) const;
};

#endif // BITCOIN_RPC_UTIL_H
