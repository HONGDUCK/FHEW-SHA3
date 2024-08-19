#include "sha3.h"
#include "binfhecontext.h"
#include <iostream>
using namespace std;
using namespace lbcrypto;

void printLWEParam(LWECiphertext ct){
    cout << "Print LWE Parameters\n";
    cout << "LWE Dimension          : " << ct->GetLength()                   << "\n";
    cout << "LWE Modulus            : " << ct->GetModulus().ConvertToInt()   << "\n"; // 134215681 ??
    cout << "LWE Plaintetxt Modulus : " << ct->GetptModulus().ConvertToInt() << "\n";
}

LWECiphertext CiphertextAddition(LWECiphertext ct0, LWECiphertext ct1, LWECiphertext ct2, LWECiphertext ct3, LWECiphertext ct4){
    LWECiphertext ctTemp = make_shared<LWECiphertextImpl>(*ct0);
    ctTemp->SetptModulus(ct0->GetptModulus());
    auto RES_A = ct0->GetA().ModAdd(ct1->GetA().ModAdd(ct2->GetA().ModAdd(ct3->GetA().ModAdd(ct4->GetA()))));
    auto RES_B = ct0->GetB().Add(ct1->GetB().Add(ct2->GetB().Add(ct3->GetB().Add(ct4->GetB()))));
    ctTemp->SetA(RES_A); ctTemp->SetB(RES_B);

    return ctTemp;
}

LWECiphertext CiphertextAddition2(LWECiphertext ct0, LWECiphertext ct1, LWECiphertext ct2, LWECiphertext ct3){
    LWECiphertext ctTemp = make_shared<LWECiphertextImpl>(*ct0);
    ctTemp->SetptModulus(ct0->GetptModulus());
    auto RES_A = ct0->GetA().ModAdd(ct1->GetA().ModAdd(ct2->GetA().ModAdd(ct3->GetA())));
    auto RES_B = ct0->GetB().Add(ct1->GetB().Add(ct2->GetB().Add(ct3->GetB())));
    ctTemp->SetA(RES_A); ctTemp->SetB(RES_B);

    return ctTemp;
}


int main(){
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128_FP);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    auto ct00 = cc.Encrypt(sk, 0, SMALL_DIM, 2);
    auto ct01 = cc.Encrypt(sk, 1, SMALL_DIM, 2);
    auto ct02 = cc.Encrypt(sk, 0, SMALL_DIM, 2);
    auto ct03 = cc.Encrypt(sk, 1, SMALL_DIM, 2);
    auto ct04 = cc.Encrypt(sk, 0, SMALL_DIM, 2);

    auto ct10 = cc.Encrypt(sk, 1, SMALL_DIM, 2);
    auto ct11 = cc.Encrypt(sk, 1, SMALL_DIM, 2);
    auto ct12 = cc.Encrypt(sk, 0, SMALL_DIM, 2);
    auto ct13 = cc.Encrypt(sk, 0, SMALL_DIM, 2);
    auto ct14 = cc.Encrypt(sk, 0, SMALL_DIM, 2);

    auto ct20 = cc.Encrypt(sk, 0, SMALL_DIM, 2);
    auto ct21 = cc.Encrypt(sk, 1, SMALL_DIM, 2);
    auto ct22 = cc.Encrypt(sk, 0, SMALL_DIM, 2);
    auto ct23 = cc.Encrypt(sk, 0, SMALL_DIM, 2);
    auto ct24 = cc.Encrypt(sk, 0, SMALL_DIM, 2);

    auto ct30 = cc.Encrypt(sk, 0, SMALL_DIM, 2);
    auto ct31 = cc.Encrypt(sk, 1, SMALL_DIM, 2);
    auto ct32 = cc.Encrypt(sk, 1, SMALL_DIM, 2);
    auto ct33 = cc.Encrypt(sk, 1, SMALL_DIM, 2);
    auto ct34 = cc.Encrypt(sk, 0, SMALL_DIM, 2);    

    LWECiphertext ctRES0, ctRES1, ctRES2, ctRES3, ctRES4;
    int err = 0;
    
    // cout << ct00->GetB().ConvertToInt() << "\n";
    // cout << ct01->GetB().ConvertToInt() << "\n";
    // cout << ct00->GetB().Add(ct01->GetB()).ConvertToInt() << "\n";
    // cout << ct00->GetB().ConvertToInt() << "\n";
    // cout << ct01->GetB().ConvertToInt() << "\n";

    for(int i=0; i<200; i++){


        ctRES0 = CiphertextAddition(ct00, ct01, ct02, ct03, ct04);
        ctRES0 = cc.EvalBinGate_overlap(XOR, ctRES0, 2);
        ctRES0 = cc.MKMSwitch_overlap(ctRES0, 2);

        ctRES1 = CiphertextAddition(ct10, ct11, ct12, ct13, ct14);
        ctRES1 = cc.EvalBinGate_overlap(XOR, ctRES1, 2);
        ctRES1 = cc.MKMSwitch_overlap(ctRES1, 2);

        ctRES2 = CiphertextAddition(ct20, ct21, ct22, ct23, ct24);
        ctRES2 = cc.EvalBinGate_overlap(XOR, ctRES2, 2);
        ctRES2 = cc.MKMSwitch_overlap(ctRES2, 2);

        ctRES3 = CiphertextAddition(ct30, ct31, ct32, ct33, ct34);
        ctRES3 = cc.EvalBinGate_overlap(XOR, ctRES3, 2);
        ctRES3 = cc.MKMSwitch_overlap(ctRES3, 2);

        ctRES4 = CiphertextAddition2(ctRES0, ctRES1, ctRES2, ctRES3);
        ctRES4 = cc.EvalBinGate_overlap(XOR, ctRES4, 4);
        ctRES4 = cc.MKMSwitch_overlap(ctRES4, 4);

        LWEPlaintext ptxt;
        cc.Decrypt(sk, ctRES4, &ptxt, 2);

        if(ptxt != 0){
            err++;
        }
    }
    cout << "Number of error : " << err << "\n";
    printLWEParam(ctRES4);

    return 0;
}
 