// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_ISMINE_H
#define BITCOIN_SCRIPT_ISMINE_H

#include <script/standard.h>

class CKeyStore;
class CScript;

bool IsMine(const CKeyStore& keystore, const CScript& scriptPubKey);
bool IsMine(const CKeyStore& keystore, const CTxDestination& dest);

#endif // BITCOIN_SCRIPT_ISMINE_H
