// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/askpassphrasedialog.h>
#include <qt/bitcoingui.h>
#include <qt/createwalletdialog.h>
#include <qt/forms/ui_createwalletdialog.h>
#include <wallet/wallet.h>

#include <QMessageBox>
#include <QProgressDialog>
#include <QString>

CreateWalletDialog::CreateWalletDialog(BitcoinGUI* parent) :
    QDialog(parent),
    ui(new Ui::CreateWalletDialog),
    m_parent(parent)
{
    ui->setupUi(this);
}

CreateWalletDialog::~CreateWalletDialog()
{
    delete ui;
}

void CreateWalletDialog::SetWalletController(WalletController* wallet_controller)
{
    this->m_wallet_controller = wallet_controller;
}

void CreateWalletDialog::accept()
{
    // Get the options
    std::string wallet_name = ui->wallet_name_line_edit->text().toStdString();
    bool disable_priv_keys = ui->disable_privkeys_checkbox->isChecked();
    bool blank = ui->blank_wallet_checkbox->isChecked();
    bool encrypt = ui->encrypt_wallet_checkbox->isChecked();

    // Get wallet creation flags
    uint64_t flags = 0;
    if (disable_priv_keys) {
        flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;
    }
    if (blank || encrypt) {
        flags |= WALLET_FLAG_BLANK_WALLET;
    }

    // Check that the wallet doesn't already exist
    if (m_wallet_controller->checkWalletExists(wallet_name)) {
        QMessageBox::critical(this, tr("Wallet creation failed"), tr("A wallet with the name <b>%1</b> already exists").arg(QString(wallet_name.c_str()).toHtmlEscaped()));
        QDialog::reject();
        return;
    }

    // Show a progress dialog
    QProgressDialog* dialog = new QProgressDialog(this);
    dialog->setLabelText(tr("Creating Wallet <b>%1</b>...").arg(QString(wallet_name.c_str()).toHtmlEscaped()));
    dialog->setRange(0, 0);
    dialog->setCancelButton(nullptr);
    dialog->setWindowModality(Qt::ApplicationModal);
    dialog->show();

    // Create the wallet
    std::unique_ptr<interfaces::Wallet> wallet = m_wallet_controller->createWallet(wallet_name, flags);

    if (wallet) {
        WalletModel* model = m_wallet_controller->getOrCreateWallet(std::move(wallet));
        // Encrypt the wallet
        if (encrypt) {
            AskPassphraseDialog dlg(AskPassphraseDialog::Encrypt, this);
            dlg.setModel(model);
            dlg.exec();
            // Set the seed after encryption
            if (!blank && !disable_priv_keys) {
                model->wallet().setNewHDSeed();
                model->wallet().topUpKeyPool();
            }
        }
        m_parent->setCurrentWallet(model);
    } else {
        QMessageBox::critical(this, tr("Wallet creation failed"), tr("Wallet creation failed due to an internal error. The wallet was not created."));
    }
    dialog->hide();
    QDialog::accept();
}
