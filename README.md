This project is a better way to do full disk encryption on Linux

# Prerequisites:

* have a yubikey (tested with yubikey 4 version 5.1.2)
* have gpg 2.x 

* Follow [these steps](https://support.yubico.com/support/solutions/articles/15000006420-using-your-yubikey-with-openpgp#Generating_Your_PGP_Key_Directly_on_Your_YubiKeyf5innj) to generate a keypair directly on your yubikey.

You may wish to install yubikey-personalization (https://github.com/Yubico/yubikey-personalization) to create udev rules making your yubikey accessable to non-root users. To install:

* Debian/Ubuntu: sudo apt install yubikey-personalization
* Fedora: sudo dnf install ykpers

