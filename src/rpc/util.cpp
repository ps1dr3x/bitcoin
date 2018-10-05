// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <keystore.h>
#include <rpc/protocol.h>
#include <rpc/util.h>
#include <tinyformat.h>
#include <utilstrencodings.h>

// Converts a hex string to a public key if possible
CPubKey HexToPubKey(const std::string& hex_in)
{
    if (!IsHex(hex_in)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key: " + hex_in);
    }
    CPubKey vchPubKey(ParseHex(hex_in));
    if (!vchPubKey.IsFullyValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key: " + hex_in);
    }
    return vchPubKey;
}

// Retrieves a public key for an address from the given CKeyStore
CPubKey AddrToPubKey(CKeyStore* const keystore, const std::string& addr_in)
{
    CTxDestination dest = DecodeDestination(addr_in);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address: " + addr_in);
    }
    CKeyID key = GetKeyForDestination(*keystore, dest);
    if (key.IsNull()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("%s does not refer to a key", addr_in));
    }
    CPubKey vchPubKey;
    if (!keystore->GetPubKey(key, vchPubKey)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("no full public key for address %s", addr_in));
    }
    if (!vchPubKey.IsFullyValid()) {
       throw JSONRPCError(RPC_INTERNAL_ERROR, "Wallet contains an invalid public key");
    }
    return vchPubKey;
}

// Creates a multisig redeemscript from a given list of public keys and number required.
CScript CreateMultisigRedeemscript(const int required, const std::vector<CPubKey>& pubkeys)
{
    // Gather public keys
    if (required < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "a multisignature address must require at least one key to redeem");
    }
    if ((int)pubkeys.size() < required) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("not enough keys supplied (got %u keys, but need at least %d to redeem)", pubkeys.size(), required));
    }
    if (pubkeys.size() > 16) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Number of keys involved in the multisignature address creation > 16\nReduce the number");
    }

    CScript result = GetScriptForMultisig(required, pubkeys);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, (strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE)));
    }

    return result;
}

class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    explicit DescribeAddressVisitor() {}

    UniValue operator()(const CNoDestination& dest) const
    {
        return UniValue(UniValue::VOBJ);
    }

    UniValue operator()(const CKeyID& keyID) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", false);
        obj.pushKV("iswitness", false);
        return obj;
    }

    UniValue operator()(const CScriptID& scriptID) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", true);
        obj.pushKV("iswitness", false);
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", false);
        obj.pushKV("iswitness", true);
        obj.pushKV("witness_version", 0);
        obj.pushKV("witness_program", HexStr(id.begin(), id.end()));
        return obj;
    }

    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("isscript", true);
        obj.pushKV("iswitness", true);
        obj.pushKV("witness_version", 0);
        obj.pushKV("witness_program", HexStr(id.begin(), id.end()));
        return obj;
    }

    UniValue operator()(const WitnessUnknown& id) const
    {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("iswitness", true);
        obj.pushKV("witness_version", (int)id.version);
        obj.pushKV("witness_program", HexStr(id.program, id.program + id.length));
        return obj;
    }
};

UniValue DescribeAddress(const CTxDestination& dest)
{
    return boost::apply_visitor(DescribeAddressVisitor(), dest);
}

bool RPCHelpUniValue::findKey(const std::string& key, size_t& retIdx) const
{
    for (size_t i = 0; i < keys.size(); i++) {
        if (keys[i] == key) {
            retIdx = i;
            return true;
        }
    }

    return false;
}

bool RPCHelpUniValue::push_back(const RPCHelpUniValue& val_)
{
    if (typ != VARR)
        return false;

    values.push_back(val_);
    return true;
}

bool RPCHelpUniValue::push_backV(const std::vector<RPCHelpUniValue>& vec)
{
    if (typ != VARR)
        return false;

    values.insert(values.end(), vec.begin(), vec.end());

    return true;
}

void RPCHelpUniValue::__pushKV(const std::string& key, const RPCHelpUniValue& val_, const std::string& m_help, bool m_required)
{
    keys.push_back(key);
    values.push_back(val_);
    helps.push_back(m_help);
    requireds.push_back(m_required);
}

bool RPCHelpUniValue::pushKV(const std::string& key, const RPCHelpUniValue& val_, const std::string& m_help, bool m_required)
{
    if (typ != VOBJ)
        return false;

    size_t idx;
    if (findKey(key, idx)) {
        values[idx] = val_;
        helps[idx] = m_help;
        requireds[idx] = m_required;
    }
    else
        __pushKV(key, val_, m_help, m_required);
    return true;
}

bool RPCHelpUniValue::pushKVs(const RPCHelpUniValue& obj)
{
    if (typ != VOBJ || obj.typ != VOBJ)
        return false;

    for (size_t i = 0; i < obj.keys.size(); i++)
        __pushKV(obj.keys[i], obj.values.at(i), obj.helps[i], obj.requireds[i]);

    return true;
}

std::string RPCHelpUniValue::WriteUniv(unsigned int prettyIndent, unsigned int indentLevel) const
{
    return UniValue::write(prettyIndent, indentLevel);
}

std::string RPCHelpUniValue::write(unsigned int pretty_indent, unsigned int indent_level) const
{
    std::vector<std::string> left;
    GetLeft(pretty_indent, indent_level, left);
    std::vector<std::string> right;
    GetRight(right);
    assert(left.size() == right.size());

    // Find longest left string
    size_t n_spaces = 0;
    for (const std::string& str : left) {
        if (str.size() > n_spaces) {
            n_spaces = str.size();
        }
    }
    n_spaces += 4;

    // Join everything together with correct spacing
    std::string s;
    s.reserve(1024);
    for (size_t i = 0; i < left.size(); ++i) {
        s += left[i];
        s.append(n_spaces - left[i].size() , ' ');
        s += right[i];
        s += "\n";
    }

    return s;
}

static void IndentStr(unsigned int pretty_indent, unsigned int indent_level, std::string& s)
{
    s.append(pretty_indent * indent_level, ' ');
}

void RPCHelpUniValue::GetLeft(unsigned int pretty_indent, unsigned int indent_level, std::vector<std::string>& out) const
{
    unsigned int mod_indent = indent_level;
    if (mod_indent == 0)
        mod_indent = 1;

    switch (typ) {
    case VOBJ:
        GetObjectLeft(pretty_indent, mod_indent, out);
        break;
    case VARR:
        GetArrayLeft(pretty_indent, mod_indent, out);
        break;
    default:
        out.push_back(WriteUniv(pretty_indent, indent_level));
        break;
    }
}

void RPCHelpUniValue::GetRight(std::vector<std::string>& out) const
{
    switch (typ) {
    case VOBJ:
        GetObjectRight(out);
        break;
    case VARR:
        GetArrayRight(out);
        break;
    default:
        out.push_back(std::string("(") + uvTypeName(typ) + (required ? " required) " : " optional) ") + help);
        break;
    }
}

void RPCHelpUniValue::GetArrayLeft(unsigned int pretty_indent, unsigned int indent_level, std::vector<std::string>& out) const
{
    std::string open_brace;
    IndentStr(pretty_indent, indent_level, open_brace);
    open_brace += "[";
    out.push_back(open_brace);

    for (unsigned int i = 0; i < values.size(); i++) {
        std::vector<std::string> arr_vals;
        values[i].GetLeft(pretty_indent, 0, arr_vals);
        for (const std::string& arr_val : arr_vals) {
            std::string indent;
            IndentStr(pretty_indent, indent_level + 1, indent);
            out.push_back(indent + arr_val);
        }
        std::string ellipsis;
        IndentStr(pretty_indent, indent_level + 1, ellipsis);
        out.push_back(ellipsis + ",...");
    }

    std::string close_brace;
    IndentStr(pretty_indent, indent_level, close_brace);
    close_brace += "]";
    out.push_back(close_brace);
}

void RPCHelpUniValue::GetArrayRight(std::vector<std::string>& out) const
{
    if (!help.empty()) {
        out.push_back(std::string("(array, ") + (required ? "required" : "optional") + ") " + help);
    } else {
        out.push_back("");
    }

    for (unsigned int i = 0; i < values.size(); i++) {
        values[i].GetRight(out);
        out.push_back("");
    }

    out.push_back("");
}

void RPCHelpUniValue::GetObjectLeft(unsigned int pretty_indent, unsigned int indent_level, std::vector<std::string>& out) const
{
    std::string open_brace;
    IndentStr(pretty_indent, indent_level, open_brace);
    open_brace += "{";
    out.push_back(open_brace);

    for (unsigned int i = 0; i < keys.size(); i++) {
        std::string s;
        IndentStr(pretty_indent, indent_level, s);
        s += "\"" + keys[i] + "\":";
        if (values.at(i).typ != VARR && values.at(i).typ != VOBJ) {
            s += " " + values.at(i).WriteUniv(pretty_indent, indent_level + 1);
            out.push_back(s);
        } else {
            out.push_back(s);
            values.at(i).GetLeft(pretty_indent, indent_level + 1, out);
        }
        if (i != (values.size() - 1))
            out.back() += ",";
    }

    std::string close_brace;
    IndentStr(pretty_indent, indent_level, close_brace);
    close_brace += "}";
    out.push_back(close_brace);
}

void RPCHelpUniValue::GetObjectRight(std::vector<std::string>& out) const
{
    if (!help.empty()) {
        out.push_back(std::string("(object, ") + (required ? "required" : "optional") + ") " + help);
    } else {
        out.push_back("");
    }

    for (unsigned int i = 0; i < keys.size(); i++) {
        values.at(i).GetRight(out);
    }

    out.push_back("");
}
