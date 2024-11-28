# FHEW-SHA3 : SHA3 with fully homomorphic encryption

We implement sha3 algorithm with <a href="https://github.com/openfheorg/openfhe-development"> OpenFHE library</a> v 1.2.0.
To make it efficient, we use <a href="https://eprint.iacr.org/2024/1667"> overlapped bootstrapping</a>.

# How to Run

* Clone this repository
```
git clone https://github.com/HONGDUCK/SHA3-with-FHE.git
```

* Change directory and build cmake
```
cd FHEW-SHA3
cmake -DNATIVE_SIZE=32
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
./sha3
./sha3_overlapped
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
    // We use parameter : LPF_STD128
    cc.GenerateBinFHEContext(LPF_STD128);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    // To measure operation time we use chrono library
    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();

    // Call sha3 class
    SHA3 ss;
    
    // Initialize crypto context
    ss.init(cc);
    
    // set debug_mode true
    ss.set_Debug_mode(sk);

    // set number of multithread : default is 1
    ss.set_multi_threads(8);

    // Initializae test string : test
    string data = "test";
    
    // generate state
    ss.state_gen(data, sk);

    // execute sha3 algorithm
    ss.build_hash();

    // print digest(result)
    ss.printdigest(2, sk);

    // end measuring
    std::chrono::duration<double>sec = std::chrono::system_clock::now() - start;

    // print measured operation time
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
    // We use parameter : LPF_STD128
    cc.GenerateBinFHEContext(LPF_STD128);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    // To measure operation time we use chrono library
    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();

    // Call sha3 class
    SHA3_OverLap ss;
    
    // Initialize crypto context
    ss.init(cc);
    
    // set debug_mode true
    ss.set_Debug_mode(sk);

    // set number of multithread : default is 1
    ss.set_multi_threads(8);

    // Initializae test string : test
    string data = "test";
    
    // generate state
    ss.state_gen(data, sk);

    // execute sha3 algorithm
    ss.build_hash();

    // print digest(result)
    ss.printdigest(2, sk);

    // end measuring
    std::chrono::duration<double>sec = std::chrono::system_clock::now() - start;

    // print measured operation time
    cout << "process time : " << sec.count() << "sec\n\n";

    return 0;
}
```

This is example for `SHA3_OverLap`.

In the examples provided, we use 8 threads.
You can easily set the number of threads by using `ss.set_multi_threads(num)`.
The default value is 1.





