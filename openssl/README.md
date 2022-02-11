# note & prerequisites
please check openssl in the local machine
the source code is executed vscode

# how to build
₩₩₩
gcc -Wall main.cpp -o main -/usr/local/include -L/usr/local/lib -lssl -lcrypto
₩₩₩

# how to run
₩₩₩
./main
₩₩₩

# result of example
₩₩₩
Pivate key: C67CB01BF93C02C353BA4EEFE4735831F75DAC27DBB43EAA5FB796863DA935E1
Public key: 030B94AD695A526CD1D069BE8FFF072AD4DDFCF3443A1C4A520AB37A1E03AAB9F5
Hash of Msg: e485b23a724260ef118f06996a0093b0c1733a30ced1a3d447a4917e119c7648
Signature     : 304402204fd44cb20ad378f756c133e9436b396fc43c54cf7740e9d10ad627a72ff869ad02204e59fb5d3f8c5eb326dba0a140d162554947cfb90aa66db77709441e91413c0f
Verification    successfulI
₩₩₩