// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/ismine.h>

#include <keystore.h>
#include <script/script.h>
#include <script/standard.h>

bool IsMine(const CKeyStore& keystore, const CScript& scriptPubKey)
{
    return keystore.HaveWatchOnly(scriptPubKey) || keystore.HaveScriptPubKey(scriptPubKey);
}

bool IsMine(const CKeyStore& keystore, const CTxDestination& dest)
{
    CScript script = GetScriptForDestination(dest);
    return IsMine(keystore, script);
}
