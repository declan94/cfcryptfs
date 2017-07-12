# cfcryptfs



## About

Cfcryptfs is an extensible encrypted filesystem implemented on FUSE (Filesystem in User Space) for linux, 
inspired by some excellent ideas from [gocryptfs](https://github.com/rfjakob/gocryptfs), [encfs](https://github.com/vgough/encfs) and [securefs](https://github.com/netheril96/securefs)

As the value of data becomes more and more important, security of data is getting more and more attention. We want our critical private data to be safe and confidential, which means people without authorization should have no chance to access or temper your data. Cfcryptfs can help you achieve this simply. Using cfcryptfs, only encrypted data will be stored on disk.

Further more, many people and companies choose to store their files and data on Internet storage services nowadays, such as Google Drive, AWS S3, Alibaba OSS and Alibaba NAS. Despite the greate convenient these Internet storage services bring to us, they also bring us risks like leak of confidential data, malicious tampering of data. Using cfcryptfs can avoid these risks by encrypting your files and data in a total secure way before uploading them to those internet storage services. Also, the process of encryption and decryption is transparent to users and programs. 

## Platform

Cfcryptfs now only supports linux system. Supports for other systems are under developing.

## Install

For now, you can only install cfcryptfs by source code. You have to install go tools first, see [here](https://golang.org/doc/install#install)

After that, execute commands below:
```
$ go get -u github.com/Declan94/cfcryptfs
$ sudo cp `go env GOPATH`/bin/cfcryptfs /usr/local/bin
```

## Usage

#### Step 1 - initialize a cipher dir
```
$ mkdir CIPHERDIR
$ cfcryptfs -init CIPHERDIR
```
You will have to choose the encryption method, block size and whether to encryption file path.
After that, you need to enter a password, it's very important to remember your password.

#### Step 2 - mount the cipher dir
```
$ mkdir PLAINDIR
$ cfcryptfs CIPHERDIR PLAINDIR
```
You will be asked to enter the password.

#### Step 3 - work in plaintext dir
Now you can work in the PLAINDIR as usual, while your files will be encrypted and stored in CIPHERDIR automatically.
After unmount the filesystem by ```sudo umount PLAINDIR```, you can see PLAINDIR is actually still an empty directory.

You can sync your CIPHER dir with any Network Access Storage without worrying leak of your confidential data, and mount to anywhere with cfcryptfs when you want to use or modify your files.

## Features

#### Extensible
Support multiple core encryption methods(AES128/AES192/AES256).  You can also create your own encryption methods by implementing ```corecrypter.CoreCrypter``` interface. The 'example' subfolder gives some simple examples.

#### Flexible
Besides encryption methods, You can also choose different encryption block size, whether encrypt filepath, etc. This is important because different application and work environment often have different demands for the filesystem.

#### Secure
* Random IV for file and blocks provides random encryption pattern.
* HMAC signature for file header provides resistence to file mode tamper. 
* HMAC signature with file IV and block id included in the key provides resistance to content tamper and block copying tamper.
* Generated IV from fullpath for filepath encryption provides resistance to file moving tamper. (in encrypted filepath mode)



