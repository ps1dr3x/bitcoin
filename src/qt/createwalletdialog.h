// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CREATEWALLETDIALOGG_H
#define BITCOIN_QT_CREATEWALLETDIALOGG_H

#include <qt/walletcontroller.h>

#include <QDialog>

class BitcoinGUI;
class WalletModel;

namespace Ui {
    class CreateWalletDialog;
}

/** Dialog for creating wallets
 */
class CreateWalletDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CreateWalletDialog(BitcoinGUI *parent);
    ~CreateWalletDialog();

    void accept();

    void SetWalletController(WalletController *wallet_controller);

private:
    Ui::CreateWalletDialog *ui;
    WalletController *m_wallet_controller;
    BitcoinGUI* m_parent;
};

#endif // BITCOIN_QT_CREATEWALLETDIALOGG_H
