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

    SHA3 ss;   ss.init(cc);
    SHA3_OverLap sso;   sso.init(cc, sk);
    string data = "test";
    
    cout << "Function test :: SHA3 without overlapped START\n";

    std::chrono::duration<double> sha3_theta_duration = std::chrono::duration<double>::zero();
    std::chrono::duration<double> sha3_chi_duration = std::chrono::duration<double>::zero();

    for(int i=0; i<5; i++){
        ss.state_gen(data, sk);

        std::chrono::system_clock::time_point sha3_theta_start = std::chrono::system_clock::now();
        ss.theta();
        std::chrono::duration<double> sha3_theta_end = std::chrono::system_clock::now() - sha3_theta_start;

        std::chrono::system_clock::time_point sha3_chi_start = std::chrono::system_clock::now();
        ss.chi();
        std::chrono::duration<double> sha3_chi_end = std::chrono::system_clock::now() - sha3_chi_start;   


        sha3_theta_duration += sha3_theta_end;
        sha3_chi_duration += sha3_chi_end;
    }

    cout << "Function test :: SHA3 without overlapped END ::\n"
         << "-----------------------------------------------\n"
         << "Function test :: SHA3 with overlapped START    \n";

    std::chrono::duration<double> sha3_overlapped_theta_duration = std::chrono::duration<double>::zero();
    std::chrono::duration<double> sha3_overlapped_chi_duration = std::chrono::duration<double>::zero();

    for(int i=0; i<5; i++){
        sso.state_gen(data, sk);

        std::chrono::system_clock::time_point sha3_overlapped_theta_start = std::chrono::system_clock::now();
        sso.theta();
        std::chrono::duration<double> sha3_overlapped_theta_end = std::chrono::system_clock::now() - sha3_overlapped_theta_start;

        std::chrono::system_clock::time_point sha3_overlapped_chi_start = std::chrono::system_clock::now();
        sso.chi();
        std::chrono::duration<double> sha3_overlapped_chi_end = std::chrono::system_clock::now() - sha3_overlapped_chi_start;   

        sha3_overlapped_theta_duration += sha3_overlapped_theta_end;
        sha3_overlapped_chi_duration += sha3_overlapped_chi_end;
    }

    cout << "Function test :: SHA3 with overlapped END ::\n"
         << "-----------------------------------------------\n"
         << "Concolusion\n"
         << ":: SHA3 without overlapped bootstrapping \n"
         << "Theta step :  total time - " << sha3_theta_duration.count() << " average time - " << sha3_theta_duration.count()/5 << "\n"
         << "Chi step :  total time - " << sha3_chi_duration.count() << " average time - " << sha3_chi_duration.count()/5 << "\n"
         << ":: SHA3 with overlapped bootstrapping \n"
         << "Theta step :  total time - " << sha3_overlapped_theta_duration.count() << " average time - " << sha3_overlapped_theta_duration.count()/5 << "\n"
         << "Chi step :  total time - " << sha3_overlapped_chi_duration.count() << " average time - " << sha3_overlapped_chi_duration.count()/5 << "\n";    

    return 0;
}