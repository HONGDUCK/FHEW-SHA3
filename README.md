# FHEW-SHA3 : SHA3 with fully homomorphic encryption

We implement sha3 algorithm with <a href="https://github.com/openfheorg/openfhe-development"> OpenFHE library</a> v 1.2.0.

# How to Run

* Clone this repository
```
git clone https://github.com/HONGDUCK/FHEW-SHA3.git
```

* Change directory and build cmake
```
cd openfhe-development
cmake -S . -B build 
```

* Change directory again and build make
```
cd build
make
```

* Execute examples
```
cd bin/examples/binfhe
./main
```

# Simple explain about sha3 code.

You can easily find sha3 code in `src/binfhe/include` and `src/binfhe/lib`

There are two classes `SHA3` and `SHA3_OverLap`

`SHA3_OverLap` is sha3 algorithm with overlapped bootstrapping technique, it is faster than `SHA3`

```cpp
#include "sha3-overlap.h"
#include "sha3.h"
#include "binfhecontext.h"
#include <iostream>
using namespace std;
using namespace lbcrypto;

int main(){
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(LPF_STD128);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
    SHA3 ss;    ss.init(cc);
    string data = "test";
    ss.state_gen(data, sk);
    ss.build_hash();
    ss.printdigest(2, sk);
    std::chrono::duration<double>sec = std::chrono::system_clock::now() - start;

    cout << "process time : " << sec.count() << "sec\n\n";

    return 0;
}
```
This is example for `SHA3`.

```cpp
#include "sha3-overlap.h"
#include "sha3.h"
#include "binfhecontext.h"
#include <iostream>
using namespace std;
using namespace lbcrypto;

int main(){
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(LPF_STD128);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);


    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
    SHA3_OverLap ss;    ss.init(cc, sk);
    string data = "test";
    ss.state_gen(data, sk);
    ss.build_hash();
    ss.printdigest(2, sk);
    std::chrono::duration<double>sec = std::chrono::system_clock::now() - start;
    
    cout << "process time : " << sec.count() << "sec\n\n";

    return 0;
}
```

This is example for `SHA3_OverLap`.






