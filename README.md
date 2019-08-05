This project is a better way to do full disk encryption on Linux

# Prerequisites:

* have a yubikey (tested with yubikey 4 version 5.1.2)
* have gpg 2.x 

* Follow [these steps](https://support.yubico.com/support/solutions/articles/15000006420-using-your-yubikey-with-openpgp#Generating_Your_PGP_Key_Directly_on_Your_YubiKeyf5innj)
to generate a keypair directly on your yubikey.

  * declare a user pin
  * declare an admin pin

# Python talking to yubikey

To check your computer can see your yubikey go here and copy the test example script to print the version of the yubikey:
https://github.com/Yubico/python-yubico

When you run it if you instead get the error:
"insufficient permissions" appearing in the stacktrace you can go and figure out which file you need access to and change the ownership to your user:

`$ strace python test.py`

*revealed a line similar to:*

`open("/dev/bus/usb/001/006", O_RDWR)    = -1 EACCES (Permission denied)`

*just* before the start of the python stacktrace output.

You need sudo access to read the usb (yubikey), you can just correct for it by changing the ownership of the file 006 to your user (so you don't have to run the entire python script with sudo permissions)

`sudo chown <username> /dev/bus/usb/001/006`

*now rerunning the test example script should result in it printing out the version number*
