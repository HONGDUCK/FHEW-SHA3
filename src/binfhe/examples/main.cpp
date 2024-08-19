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

    // auto cc = BinFHEContext();
    // cc.GenerateBinFHEContext(LPF_STD128);
    // auto sk = cc.KeyGen();
    // cc.BTKeyGen(sk);


    // std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
    // SHA3_OverLap ss;    ss.init(cc, sk);
    // string data = "test";
    // ss.state_gen(data, sk);
    // ss.build_hash();
    // ss.printdigest(2, sk);
    // std::chrono::duration<double>sec = std::chrono::system_clock::now() - start;
    
    // cout << "process time : " << sec.count() << "sec\n\n";

    return 0;
}