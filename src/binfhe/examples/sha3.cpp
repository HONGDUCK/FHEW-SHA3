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