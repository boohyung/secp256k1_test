# note & prerequisites
please check openssl in the local machine  
the source code is executed vscode

# how to build
```
gcc -Wall main.cpp -o main -I/usr/local/include -L/usr/local/lib -lssl -lcrypto
```

# how to run
```
./main
```

# result of example
```
Pivate key: BE5330D3319E42308F48BF137C4421D356AEC7881E523A09974D6983BCD8FCDA
Public key: 033F6BA7FD83F75B456535C8900730709A55615340C561968CFA14311D73E8D959
Hash of Msg: e485b23a724260ef118f06996a0093b0c1733a30ced1a3d447a4917e119c7648
Signature     : 3045022019f0f4027922a5f427c43ffd456c329ff25d2230fa13f9ba09b8d770ad9526f80221008f595b4b5ef9d3c17353711e2f54da6a13363fdc0034cef04c1d0204020e52af
Verification    successful
```
