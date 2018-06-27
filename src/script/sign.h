// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGN_H
#define BITCOIN_SCRIPT_SIGN_H

#include <hash.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <streams.h>

class CKey;
class CKeyID;
class CScript;
class CScriptID;
class CTransaction;

struct CMutableTransaction;

/** An interface to be implemented by keystores that support signing. */
class SigningProvider
{
public:
    virtual ~SigningProvider() {}
    virtual bool GetCScript(const CScriptID &scriptid, CScript& script) const { return false; }
    virtual bool GetPubKey(const CKeyID &address, CPubKey& pubkey) const { return false; }
    virtual bool GetKey(const CKeyID &address, CKey& key) const { return false; }
};

extern const SigningProvider& DUMMY_SIGNING_PROVIDER;

/** Interface for signature creators. */
class BaseSignatureCreator {
public:
    virtual ~BaseSignatureCreator() {}
    virtual const BaseSignatureChecker& Checker() const =0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const =0;
};

/** A signature creator for transactions. */
class MutableTransactionSignatureCreator : public BaseSignatureCreator {
    const CMutableTransaction* txTo;
    unsigned int nIn;
    int nHashType;
    CAmount amount;
    const MutableTransactionSignatureChecker checker;

public:
    MutableTransactionSignatureCreator(const CMutableTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, int nHashTypeIn = SIGHASH_ALL);
    const BaseSignatureChecker& Checker() const override { return checker; }
    bool CreateSig(const SigningProvider& provider, std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const override;
};

/** A signature creator that just produces 72-byte empty signatures. */
extern const BaseSignatureCreator& DUMMY_SIGNATURE_CREATOR;

typedef std::pair<CPubKey, std::vector<unsigned char>> SigPair;

// This struct contains information from a transaction input and also contains signatures for that input.
// The information contained here can be used to create a signature and is also filled by ProduceSignature
// in order to construct final scriptSigs and scriptWitnesses.
struct SignatureData {
    bool complete = false; // Stores whether the scriptSig and scriptWitness are complete
    bool witness = false; // Stores whether the input this SigData corresponds to is a witness input
    CScript scriptSig; // The scriptSig of an input. Contains complete signatures or the traditional partial signatures format
    CScript redeem_script; // The redeemScript (if any) for the input
    CScript witness_script; // The witnessScript (if any) for the input. witnessScripts are used in P2WSH outputs.
    CScriptWitness scriptWitness; // The scriptWitness of an input. Contains complete signatures or the traditional partial signatures format. scriptWitness is part of a transaction input per BIP 144.
    std::map<CKeyID, SigPair> signatures; // BIP 174 style partial signatures for the input. May contain all signatures necessary for producing a final scriptSig or scriptWitness.
    std::map<CKeyID, CPubKey> misc_pubkeys;

    SignatureData() {}
    explicit SignatureData(const CScript& script) : scriptSig(script) {}
    void MergeSignatureData(SignatureData sigdata);
};



// Note: These constants are in reverse byte order because serialization uses LSB
static constexpr uint32_t PSBT_MAGIC_BYTES = 0x74627370;

// Global types
static constexpr uint8_t PSBT_GLOBAL_UNSIGNED_TX = 0x00;

// Input types
static constexpr uint8_t PSBT_IN_NON_WITNESS_UTXO = 0x00;
static constexpr uint8_t PSBT_IN_WITNESS_UTXO = 0x01;
static constexpr uint8_t PSBT_IN_PARTIAL_SIG = 0x02;
static constexpr uint8_t PSBT_IN_SIGHASH = 0x03;
static constexpr uint8_t PSBT_IN_REDEEMSCRIPT = 0x04;
static constexpr uint8_t PSBT_IN_WITNESSSCRIPT = 0x05;
static constexpr uint8_t PSBT_IN_BIP32_DERIVATION = 0x06;
static constexpr uint8_t PSBT_IN_SCRIPTSIG = 0x07;
static constexpr uint8_t PSBT_IN_SCRIPTWITNESS = 0x08;

// Output types
static constexpr uint8_t PSBT_OUT_REDEEMSCRIPT = 0x00;
static constexpr uint8_t PSBT_OUT_WITNESSSCRIPT = 0x01;
static constexpr uint8_t PSBT_OUT_BIP32_DERIVATION = 0x02;

// The separator is 0x00. Reading this in means that the unserializer can interpret it
// as a 0 length key. which indicates that this is the separator. The separator has no value.
static const uint8_t PSBT_SEPARATOR = 0x00;

template<typename Stream, typename... X>
void SerializeToVector(Stream& s, const X&... args)
{
    std::vector<unsigned char> ret;
    CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, ret, 0);
    SerializeMany(ss, args...);
    s << ret;
}

template<typename Stream, typename... X>
void UnserializeFromVector(Stream& s, X&... args)
{
    std::vector<unsigned char> data;
    s >> data;
    CDataStream ss(data, SER_NETWORK, PROTOCOL_VERSION);
    UnserializeMany(ss, args...);
    if (!ss.eof()) {
        throw std::ios_base::failure("Size of value was not the stated size");
    }
}

/** A structure for PSBTs which contain per input information */
struct PartiallySignedInput
{
    CTransactionRef non_witness_utxo;
    CTxOut witness_utxo;
    CScript redeem_script;
    CScript witness_script;
    CScript final_script_sig;
    CScriptWitness final_script_witness;
    std::map<CPubKey, std::vector<uint32_t>> hd_keypaths;
    std::map<CKeyID, SigPair> partial_sigs;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> unknown;
    int sighash_type = 0;

    bool IsNull() const;
    void FillSignatureData(SignatureData& sigdata) const;
    void FromSignatureData(const SignatureData& sigdata, bool sign = true);
    PartiallySignedInput() {}

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        // Write the utxo
        // If there is a non-witness utxo, then don't add the witness one.
        if (non_witness_utxo) {
            SerializeToVector(s, PSBT_IN_NON_WITNESS_UTXO);
            SerializeToVector(s, non_witness_utxo);
        } else if (!witness_utxo.IsNull()) {
            SerializeToVector(s, PSBT_IN_WITNESS_UTXO);
            SerializeToVector(s, witness_utxo);
        }

        if (final_script_sig.empty() && final_script_witness.IsNull()) {
            // Write any partial signatures
            for (auto sig_pair : partial_sigs) {
                SerializeToVector(s, PSBT_IN_PARTIAL_SIG, MakeSpan(sig_pair.second.first));
                s << sig_pair.second.second;
            }

            // Write the sighash type
            if (sighash_type > 0) {
                SerializeToVector(s, PSBT_IN_SIGHASH);
                SerializeToVector(s, sighash_type);
            }

            // Write the redeem script
            if (!redeem_script.empty()) {
                SerializeToVector(s, PSBT_IN_REDEEMSCRIPT);
                s << redeem_script;
            }

            // Write the witness script
            if (!witness_script.empty()) {
                SerializeToVector(s, PSBT_IN_WITNESSSCRIPT);
                s << witness_script;
            }

            // Write any hd keypaths
            for (auto keypath_pair : hd_keypaths) {
                SerializeToVector(s, PSBT_IN_BIP32_DERIVATION, MakeSpan(keypath_pair.first));
                WriteCompactSize(s, keypath_pair.second.size() * sizeof(uint32_t));
                for (auto& path : keypath_pair.second) {
                    s << path;
                }
            }
        }

        // Write script sig
        if (!final_script_sig.empty()) {
            SerializeToVector(s, PSBT_IN_SCRIPTSIG);
            s << final_script_sig;
        }
        // write script witness
        if (!final_script_witness.IsNull()) {
            SerializeToVector(s, PSBT_IN_SCRIPTWITNESS);
            SerializeToVector(s, final_script_witness.stack);
        }

        // Write unknown things
        for (auto& entry : unknown) {
            s << entry.first;
            s << entry.second;
        }

        s << PSBT_SEPARATOR;
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Read loop
        while(!s.empty()) {
            // read size of key
            uint64_t key_len = ReadCompactSize(s);

            // the key length is 0 if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key_len == 0) {
                return;
            }

            // Read key
            std::vector<unsigned char> key;
            key.resize(key_len);
            s >> MakeSpan(key);

            // First byte of key is the type
            unsigned char type = key[0];

            // Do stuff based on type
            switch(type) {
                case PSBT_IN_NON_WITNESS_UTXO:
                    if (non_witness_utxo) {
                        throw std::ios_base::failure("Duplicate Key, input non-witness utxo already provided");
                    }
                    UnserializeFromVector(s, non_witness_utxo);
                    break;
                case PSBT_IN_WITNESS_UTXO:
                    if (!witness_utxo.IsNull()) {
                        throw std::ios_base::failure("Duplicate Key, input witness utxo already provided");
                    }
                    UnserializeFromVector(s, witness_utxo);
                    break;
                case PSBT_IN_PARTIAL_SIG:
                {
                    // Make sure that the key is the size of pubkey + 1
                    if (key.size() != CPubKey::PUBLIC_KEY_SIZE + 1 && key.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1) {
                        throw std::ios_base::failure("Size of key was not the expected size for the type partial signature pubkey");
                    }
                    // Read in the pubkey from key
                    CPubKey pubkey(key.begin() + 1, key.end());
                    if (!pubkey.IsFullyValid()) {
                       throw std::ios_base::failure("Invalid pubkey");
                    }
                    if (partial_sigs.count(pubkey.GetID()) > 0) {
                        throw std::ios_base::failure("Duplicate Key, input partial signature for pubkey already provided");
                    }

                    // Read in the signature from value
                    uint64_t value_len = ReadCompactSize(s);
                    std::vector<unsigned char> sig;
                    sig.resize(value_len);
                    s >> MakeSpan(sig);

                    // Add to list
                    partial_sigs.emplace(pubkey.GetID(), SigPair(pubkey, sig));
                    break;
                }
                case PSBT_IN_SIGHASH:
                    if (sighash_type > 0) {
                        throw std::ios_base::failure("Duplicate Key, input sighash type already provided");
                    }
                    UnserializeFromVector(s, sighash_type);
                    break;
                case PSBT_IN_REDEEMSCRIPT:
                {
                    if (!redeem_script.empty()) {
                        throw std::ios_base::failure("Duplicate Key, input redeemScript already provided");
                    }
                    s >> redeem_script;
                    break;
                }
                case PSBT_IN_WITNESSSCRIPT:
                {
                    if (!witness_script.empty()) {
                        throw std::ios_base::failure("Duplicate Key, input witnessScript already provided");
                    }
                    s >> witness_script;
                    break;
                }
                case PSBT_IN_BIP32_DERIVATION:
                {
                    // Make sure that the key is the size of pubkey + 1
                    if (key.size() != CPubKey::PUBLIC_KEY_SIZE + 1 && key.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1) {
                        throw std::ios_base::failure("Size of key was not the expected size for the type BIP32 keypath");
                    }
                    // Read in the pubkey from key
                    CPubKey pubkey(key.begin() + 1, key.end());
                    if (!pubkey.IsFullyValid()) {
                       throw std::ios_base::failure("Invalid pubkey");
                    }
                    if (hd_keypaths.count(pubkey) > 0) {
                        throw std::ios_base::failure("Duplicate Key, input pubkey derivation path already provided");
                    }

                    // Read in key path
                    uint64_t value_len = ReadCompactSize(s);
                    std::vector<uint32_t> keypath;
                    for (unsigned int i = 0; i < value_len; i += sizeof(uint32_t)) {
                        uint32_t index;
                        s >> index;
                        keypath.push_back(index);
                    }

                    // Add to map
                    hd_keypaths.emplace(pubkey, keypath);
                    break;
                }
                case PSBT_IN_SCRIPTSIG:
                {
                    if (!final_script_sig.empty()) {
                        throw std::ios_base::failure("Duplicate Key, input final scriptSig already provided");
                    }
                    s >> final_script_sig;
                    break;
                }
                case PSBT_IN_SCRIPTWITNESS:
                {
                    if (!final_script_witness.IsNull()) {
                        throw std::ios_base::failure("Duplicate Key, input final scriptWitness already provided");
                    }
                    UnserializeFromVector(s, final_script_witness.stack);
                    break;
                }
                // Unknown stuff
                default:
                    if (unknown.count(key) > 0) {
                        throw std::ios_base::failure("Duplicate Key, key for unknown value already provided");
                    }
                    // Read in the value
                    uint64_t value_len = ReadCompactSize(s);
                    std::vector<unsigned char> val_bytes;
                    val_bytes.resize(value_len);
                    s >> MakeSpan(val_bytes);
                    unknown.emplace(std::move(key), std::move(val_bytes));
                    break;
            }
        }
    }

    template <typename Stream>
    PartiallySignedInput(deserialize_type, Stream& s) {
        Unserialize(s);
    }
};

/** A structure for PSBTs which contains per output information */
struct PSBTOutput
{
    CScript redeem_script;
    CScript witness_script;
    std::map<CPubKey, std::vector<uint32_t>> hd_keypaths;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> unknown;

    bool IsNull() const;
    void FillSignatureData(SignatureData& sigdata) const;
    void FromSignatureData(const SignatureData& sigdata);
    PSBTOutput() {}

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        // Write the redeem script
        if (!redeem_script.empty()) {
            SerializeToVector(s, PSBT_OUT_REDEEMSCRIPT);
            s << redeem_script;
        }

        // Write the witness script
        if (!witness_script.empty()) {
            SerializeToVector(s, PSBT_OUT_WITNESSSCRIPT);
            s << witness_script;
        }

        // Write any hd keypaths
        for (auto keypath_pair : hd_keypaths) {
            SerializeToVector(s, PSBT_OUT_BIP32_DERIVATION, MakeSpan(keypath_pair.first));
            WriteCompactSize(s, keypath_pair.second.size() * sizeof(uint32_t));
            for (auto& path : keypath_pair.second) {
                s << path;
            }
        }

        // Write unknown things
        for (auto& entry : unknown) {
            s << entry.first;
            s << entry.second;
        }

        s << PSBT_SEPARATOR;
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Read loop
        while(!s.empty()) {
            // read size of key
            uint64_t key_len = ReadCompactSize(s);

            // the key length is 0 if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key_len == 0) {
                return;
            }

            // Read key
            std::vector<unsigned char> key;
            key.resize(key_len);
            s >> MakeSpan(key);

            // First byte of key is the type
            unsigned char type = key[0];

            // Do stuff based on type
            switch(type) {
                case PSBT_OUT_REDEEMSCRIPT:
                {
                    if (!redeem_script.empty()) {
                        throw std::ios_base::failure("Duplicate Key, output redeemScript already provided");
                    }
                    s >> redeem_script;
                    break;
                }
                case PSBT_OUT_WITNESSSCRIPT:
                {
                    if (!witness_script.empty()) {
                        throw std::ios_base::failure("Duplicate Key, output witnessScript already provided");
                    }
                    s >> witness_script;
                    break;
                }
                case PSBT_OUT_BIP32_DERIVATION:
                {
                    uint64_t value_len = ReadCompactSize(s);
                    // Make sure that the key is the size of pubkey + 1
                    if (key.size() != CPubKey::PUBLIC_KEY_SIZE + 1 && key.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE + 1) {
                        throw std::ios_base::failure("Size of key was not the expected size for the type BIP32 keypath");
                    }
                    // Read in the pubkey from key
                    CPubKey pubkey(key.begin() + 1, key.end());
                    if (!pubkey.IsFullyValid()) {
                       throw std::ios_base::failure("Invalid pubkey");
                    }
                    if (hd_keypaths.count(pubkey) > 0) {
                        throw std::ios_base::failure("Duplicate Key, output pubkey derivation path already provided");
                    }

                    // Read in key path
                    std::vector<uint32_t> keypath;
                    for (unsigned int i = 0; i < value_len; i += sizeof(uint32_t)) {
                        uint32_t index;
                        s >> index;
                        keypath.push_back(index);
                    }

                    // Add to map
                    hd_keypaths.emplace(pubkey, keypath);
                    break;
                }
                // Unknown stuff
                default: {
                    if (unknown.count(key) > 0) {
                        throw std::ios_base::failure("Duplicate Key, key for unknown value already provided");
                    }
                    // Read in the value
                    uint64_t value_len = ReadCompactSize(s);
                    std::vector<unsigned char> val_bytes;
                    val_bytes.resize(value_len);
                    s >> MakeSpan(val_bytes);
                    unknown.emplace(std::move(key), std::move(val_bytes));
                    break;
                }
            }
        }
    }

    template <typename Stream>
    PSBTOutput(deserialize_type, Stream& s) {
        Unserialize(s);
    }
};

/** A version of CTransaction with the PSBT format*/
struct PartiallySignedTransaction
{
    CMutableTransaction tx;
    std::vector<PartiallySignedInput> inputs;
    std::vector<PSBTOutput> outputs;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> unknown;
    uint64_t num_ins = 0;
    bool use_in_index = false;

    bool IsNull() const;
    PartiallySignedTransaction() {}
    PartiallySignedTransaction(const PartiallySignedTransaction& psbt_in) : tx(psbt_in.tx), inputs(psbt_in.inputs), outputs(psbt_in.outputs), unknown(psbt_in.unknown) {}

    // Only checks if they refer to the same transaction
    friend bool operator==(const PartiallySignedTransaction& a, const PartiallySignedTransaction &b)
    {
        return a.tx.GetHash() == b.tx.GetHash();
    }
    friend bool operator!=(const PartiallySignedTransaction& a, const PartiallySignedTransaction &b)
    {
        return !(a == b);
    }

    template <typename Stream>
    inline void Serialize(Stream& s) const {

        // magic bytes
        s << PSBT_MAGIC_BYTES << (char)0xff; // psbt 0xff

        // unsigned tx flag
        SerializeToVector(s, PSBT_GLOBAL_UNSIGNED_TX);

        // Write serialized tx to a stream
        SerializeToVector(s, tx);

        // Write the unknown things
        for (auto& entry : unknown) {
            s << entry.first;
            s << entry.second;
        }

        // Separator
        s << PSBT_SEPARATOR;

        // Write inputs
        for (const PartiallySignedInput& input : inputs) {
            s << input;
        }
        // Write outputs
        for (const PSBTOutput& output : outputs) {
            s << output;
        }
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        // Read the magic bytes
        int magic;
        s >> magic;
        if (magic != PSBT_MAGIC_BYTES) {
            throw std::ios_base::failure("Invalid PSBT magic bytes");
        }
        unsigned char magic_sep;
        s >> magic_sep;

        // Read global data
        while(!s.empty()) {
            // read size of key
            uint64_t key_len = ReadCompactSize(s);

            // the key length is 0 if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key_len == 0) {
                break;
            }

            // Read key
            std::vector<unsigned char> key;
            key.resize(key_len);
            s >> MakeSpan(key);

            // First byte of key is the type
            unsigned char type = key[0];

            // Do stuff based on type
            switch(type) {
                case PSBT_GLOBAL_UNSIGNED_TX:
                    if (!CTransaction(tx).IsNull()) {
                        throw std::ios_base::failure("Duplicate Key, unsigned tx already provided");
                    }
                    UnserializeFromVector(s, tx);
                    // Make sure that all scriptSigs and scriptWitnesses are empty
                    for (const CTxIn& txin : tx.vin) {
                        if (!txin.scriptSig.empty() || !txin.scriptWitness.IsNull()) {
                            throw std::ios_base::failure("Unsigned tx does not have empty scriptSigs and scriptWitnesses.");
                        }
                    }
                    break;
                // Unknown stuff
                default: {
                    if (unknown.count(key) > 0) {
                        throw std::ios_base::failure("Duplicate Key, key for unknown value already provided");
                    }
                    // Read in the value
                    uint64_t value_len = ReadCompactSize(s);
                    std::vector<unsigned char> val_bytes;
                    val_bytes.resize(value_len);
                    s >> MakeSpan(val_bytes);
                    unknown.emplace(std::move(key), std::move(val_bytes));
                }
            }
        }

        // Make sure that we got an unsigned tx
        if (CTransaction(tx).IsNull()) {
            throw std::ios_base::failure("No unsigned transcation was provided");
        }

        // Read input data
        unsigned int i = 0;
        while (!s.empty() && i < tx.vin.size()) {
            PartiallySignedInput input;
            s >> input;
            inputs.push_back(input);

            // Make sure the non-witness utxo matches the outpoint
            if (input.non_witness_utxo && input.non_witness_utxo->GetHash() != tx.vin[i].prevout.hash) {
                throw std::ios_base::failure("Non-witness UTXO does not match outpoint hash");
            }
            ++i;
        }
        // Make sure that the number of inputs matches the number of inputs in the transaction
        if (inputs.size() != tx.vin.size()) {
            throw std::ios_base::failure("Inputs provided does not match the number of inputs in transaction.");
        }

        // Read output data
        i = 0;
        while (!s.empty() && i < tx.vout.size()) {
            PSBTOutput output;
            s >> output;
            outputs.push_back(output);
            ++i;
        }
        // Make sure that the number of outputs matches the number of outputs in the transaction
        if (outputs.size() != tx.vout.size()) {
            throw std::ios_base::failure("Outputs provided does not match the number of outputs in transaction.");
        }
    }

    template <typename Stream>
    PartiallySignedTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }
};

/** Produce a script signature using a generic signature creator. */
bool ProduceSignature(const SigningProvider& provider, const BaseSignatureCreator& creator, const CScript& scriptPubKey, SignatureData& sigdata);

/** Produce a script signature for a transaction. */
bool SignSignature(const SigningProvider &provider, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, const CAmount& amount, int nHashType);
bool SignSignature(const SigningProvider &provider, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType);

/** Extract signature data from a transaction input, and insert it. */
SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn, const CTxOut& txout);
void UpdateInput(CTxIn& input, const SignatureData& data);

/* Check whether we know how to sign for an output like this, assuming we
 * have all private keys. While this function does not need private keys, the passed
 * provider is used to look up public keys and redeemscripts by hash.
 * Solvability is unrelated to whether we consider this output to be ours. */
bool IsSolvable(const SigningProvider& provider, const CScript& script);

class SignatureExtractorChecker : public BaseSignatureChecker
{
private:
    SignatureData* sigdata;
    BaseSignatureChecker* checker;

public:
    SignatureExtractorChecker(SignatureData* sigdata, BaseSignatureChecker* checker) : sigdata(sigdata), checker(checker) {}
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override;
};

#endif // BITCOIN_SCRIPT_SIGN_H
