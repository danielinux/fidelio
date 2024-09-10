# Windows Quirks

While Fidelio can be compiled for a Pico on a Windows PC there are some requirements that are atypical for most Windows users, this note will explain some of the ways to get around the deficiencies of Windows when it comes to developing for the Pico.

### The Problem

As Fidelio is part of a hardware security device it requires a cryptographically secure CERTIFICATE as part of it's functioning (something like how HTTPS works but even more secure). This certificate is part of the security system Fidelio uses and is, itself, used by Fidelio to create further certificates required to make Fidelio a safe system to use.

The creation of a certificate requires a few utilities usually only found on Linux systems.

While we could supply a default certificate this does create a potential security issue when creating a secure device so the decision was made to rely on the user creating their own certificate.

### The Solution(s)

Fidelio requires access to recent versions of the openssl, sed and xxd command-line utilities

The most obvious way to obtain these programs is by installing WSL, another way is to install Msys2. Both these methods will allow a Linux-like experience (but are beyond the scope of this note and left to the reader to research if they desire)

### Windows Native

A slightly more complex, but having the advantage that it will work directly under Windows, method is to download Windows native versions of the three utilities required and making sure they are available from the command line.

#### openssl

There are many options at https://wiki.openssl.org/index.php/Binaries choose one of the "OpenSSL for Windows" versions (I chose the firedeamon one) and install it. Depending on the installer you use if you see the option to add OpenSSL to your path make sure you do that, otherwise you will need to manually add the installation directory to your path

#### sed

Get the installer (the one with setup in it's name) from https://sourceforge.net/projects/gnuwin32/files/sed/ then use setup to install the program.

You will need to manually add the installation directory to your path

#### xxd

Get the zip from https://sourceforge.net/projects/xxd-for-windows/ Use your favourite UnZipping utility to extract the contents somewhere on your drive. You will need to manually add the location where sed.exe is to your path (I have a directory called C:\utils specifically for stuff like this)

#### Test

To make sure the above utilities are installed correctly open a command prompt and enter the following commands....

openssl -h
sed -h
xxd -h

All three should display some usage information. If they don't then you've most likely not added them to your path correctly

#### Create your certificate

Once you're happy everything above works open a command prompt and change to the Fidelio top-level directory

Now type ...

.\makecert.bat

This should create a bunch of files (you can ignore) and also create src/cert.c (which is vitally important)

You can personalise the certificate makecert creates by using a text editor (or using in VSCode?) to alter the file attestation-cert.conf. The default entries in the supplied version are largely nonsense so you might want to make them more relevant to you. Simply alter the entries after the equals (=) on any line you want to change to better suit your liking

