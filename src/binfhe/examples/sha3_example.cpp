#include <iostream>
#include <chrono>
#include <string>
#include <bitset>
#include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;

typedef vector<LWECiphertext> vec_LWE;
typedef vector<vec_LWE> sha_state;

struct param_sha3{
    string data;

    vec_LWE ct;
    vec_LWE PaddingBlock;
    sha_state h;
};
auto cc = BinFHEContext();

int u_mod(int x, int modN);
void rotate_left(vec_LWE& ct, size_t index);
vec_LWE temp_rotate_left(vec_LWE ct, size_t index);
vec_LWE bitwiseXor(vec_LWE ct1, vec_LWE ct2, PlaintextModulus p);
vec_LWE bitwiseAnd(vec_LWE ct1, vec_LWE ct2);
vec_LWE bitwiseNot(vec_LWE ct1);

vec_LWE EncForHash(string data, ConstLWEPrivateKey sk);
sha_state stateGen(ConstLWEPrivateKey sk);
vec_LWE HexaGen(string hexa, ConstLWEPrivateKey sk);
vec_LWE PadBlockGen(ConstLWEPrivateKey sk);
param_sha3 ParamGen(string data, ConstLWEPrivateKey sk);

void theta(sha_state& A);
void ryo(sha_state& A);
void pi(sha_state& A);
void chi(sha_state& A);
void iota_v2(sha_state& A, int round);
void rounding_Func(sha_state& A);
void MesXOR(vec_LWE ct, size_t start_index, sha_state& h);

vec_LWE sha_3(param_sha3 param);

LWEPrivateKey sk;
void printState(sha_state h, PlaintextModulus p){
    /* print */
    for(int i=0; i<=16; i++){
        cout << "h[" << i << "] : ";

        LWEPlaintext res;
        for(int j=0; j<64; j++){
            if(j % 8 == 0) cout << " ";
            cc.Decrypt(sk, h[i][j], &res, p);
            cout << res;
        }

        cout << "\n";
    }
}

void printCT(vec_LWE CT){
    LWEPlaintext res;
    auto p = CT[0]->GetptModulus().ConvertToInt();
    for (size_t i = 0; i < CT.size(); i++){
        if(i != 0 && i % 8 == 0) cout << " ";
        cc.Decrypt(sk, CT[i], &res, p);
        cout << res;
    }
    cout << "\n";
}

vec_LWE create_copy(vec_LWE const &vec){

    vec_LWE v;
    for (size_t i = 0; i < vec.size(); i++){
        auto ct = cc.EvalNOT(vec[i]);
        ct = cc.EvalNOT(ct);

        v.push_back(ct);
    }

    return v;
}

int main(){
    cc.GenerateBinFHEContext(LPF_STD128);
    sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    /* a * 300 */
    string test = "test";
    param_sha3 param = ParamGen(test, sk);
    
    std::chrono::system_clock::time_point start = std::chrono::system_clock::now();
    vec_LWE tempCt = sha_3(param);
    std::chrono::duration<double>sec = std::chrono::system_clock::now() - start;
    
    cout << "\n\nInput Data : " << test << "\n";
    cout << "HashValue Size : " << tempCt.size() << "\n";
    cout << "process time : " << sec.count() << "sec\n\n";

    cout << "Decrypted Value\n";
    vector<LWEPlaintext> ans;
    for(size_t i=0; i<tempCt.size(); i++){
        LWEPlaintext res;
        cc.Decrypt(sk, tempCt[i], &res, 2);
        ans.push_back(res);
    }

    for(size_t i=0; i<ans.size(); i++){
        if(i % 8 == 0) cout << " ";
        if(i % 16 == 0) cout << "\n";

        cout << ans[i];
    }
    cout << "\n";

    return 0;
}

int u_mod(int x, int modN){
    if(x % modN >= 0 ){
        return x % modN;
    }else{
        return modN + (x % modN);
    }
}

void rotate_left(vec_LWE& ct, size_t index){
    /**
     * 64bit 구격
     * */

    size_t ctLen = ct.size();
    index %= ctLen;
    
    vec_LWE temp;
    for(size_t i=index; i<ctLen; i++){
        temp.push_back(ct[i]);
    }

    for(size_t i=0; i<index; i++){
        temp.push_back(ct[i]);
    }

    while (!ct.empty()){
        ct.pop_back();
    }

    for(size_t i=0; i<temp.size(); i++){
        ct.push_back(temp[i]);
    }    
}

vec_LWE temp_rotate_left(vec_LWE ct, size_t index){
    /**
     * 64bit 구격
     * */    

    size_t ctLen = ct.size();
    index %= ctLen;
    
    vec_LWE temp;
    for(size_t i=index; i<ctLen; i++){
        temp.push_back(ct[i]);
    }

    for(size_t i=0; i<index; i++){
        temp.push_back(ct[i]);
    }

    while (!ct.empty()){
        ct.pop_back();
    }

    for(size_t i=0; i<temp.size(); i++){
        ct.push_back(temp[i]);
    }

    return ct;
}

vec_LWE bitwiseXor(vec_LWE ct1, vec_LWE ct2, PlaintextModulus p){
    /**
     * 64bit 타겟, bitwise XOR 연산
     * Parallel?
    */
    
    vec_LWE temp;
    size_t ctLen = ct1.size(); // 64bit

    for(size_t i=0; i<ctLen; i++){
        temp.push_back(cc.EvalBinGate_rescaling(XOR, ct1[i], ct2[i], p));
    }

    return temp;
}

vec_LWE bitwiseNot(vec_LWE ct1){
    // for 4/q
    vec_LWE temp;
    size_t ctLen = ct1.size();

    for(size_t i=0; i<ctLen; i++){
        temp.push_back(cc.EvalNOT(ct1[i]));
    }

    return temp;
}

vec_LWE bitwiseAnd(vec_LWE ct1, vec_LWE ct2){
    /**
     * 64비트 타겟, bitwise AND 연산
     * Parallel?
    */
    vec_LWE temp;
    size_t ctLen = ct1.size();

    for(size_t i=0; i<ctLen; i++){
        temp.push_back(cc.EvalBinGate_rescaling(AND, ct1[i], ct2[i], 2));
    }

    return temp;
}

vec_LWE EncForHash(string data, ConstLWEPrivateKey sk){
    vec_LWE temp;
    size_t len = data.size();

    for(int i=len-1; i>=0; i--){
        bitset<8> b( (char)data[i] );

        for(int j=b.size()-1; j>=0; j--){
            temp.push_back(cc.Encrypt(sk, b[j], SMALL_DIM, 2));
        }
    }

    return temp;
}

sha_state stateGen(ConstLWEPrivateKey sk){
    sha_state state;
    for(size_t i=0; i<25; i++){
        vec_LWE temp;
        for(size_t j=0; j<64; j++){
            temp.push_back(cc.Encrypt(sk, 0, SMALL_DIM, 2));
        }
        state.push_back(temp);
    }

    return state;
}

/**
 * 16진수를 string으로 받아 암호화된 4bit로 연산해주는 함수.
*/
vec_LWE HexaGen(string hexa, ConstLWEPrivateKey sk){
    vec_LWE temp;
    
    for(int i=0; i<(int)hexa.size(); i++){
        if(hexa[i] >= 48 && hexa[i] <= 57){ // 0 ~ 9
            bitset<4> b(hexa[i] - 48);
            for(int j=b.size()-1; j>=0; j--){
                temp.push_back(cc.Encrypt(sk, b[j], SMALL_DIM, 2));
            }
        }else{ // A ~ F
            bitset<4> b(hexa[i] - 55);
            for(int j=b.size()-1; j>=0; j--){
                temp.push_back(cc.Encrypt(sk, b[j], SMALL_DIM, 2));
            }
        }
    }

    return temp;
}

vec_LWE PadBlockGen(ConstLWEPrivateKey sk){
    vec_LWE temp;
    for(size_t i=0; i<1088; i++){
        temp.push_back(cc.Encrypt(sk, 0, SMALL_DIM, 2));
    }

    return temp;
}

void MesXOR(vec_LWE ct, size_t start_index, sha_state& h){
    /**
     * 17 * 64 --> 1088
     * keccak-256
    */

    for(int i=16; i>=0; i--){
        vec_LWE temp;
        for(size_t j=0; j<64; j++){
            temp.push_back(ct[(int)((int)start_index + (16-i)*64) + j]);
        }

        h[i] = bitwiseXor(temp, h[i], 2);
    }

    cout << "Mes XOR done, Round Start.\n";

    rounding_Func(h);
}

void theta(sha_state& A){
    sha_state C(5);
    sha_state D(5);


    // C[x] = A[x,0] ⊕ A[x,1] ⊕ A[x,2] ⊕ A[x,3] ⊕ A[x,4]
// #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(5))
    for(size_t i=0; i<5; i++){
        C[i] = bitwiseXor( A[i +  0],
               bitwiseXor( A[i +  5],
               bitwiseXor( A[i + 10], 
               bitwiseXor( A[i + 15], A[i + 20], 2), 2), 2), 2);
    }

    // D[x] = C[x−1] ⊕ rotation(C[x+1],1) in Z_q
// #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(5))
    for(size_t i=0; i<5; i++){
        D[i] = bitwiseXor( C[u_mod(i-1, 5)], temp_rotate_left(C[u_mod(i+1, 5)],1), 2); 
    }

    // A[x,y] = A[x,y] ⊕ D[x]
// #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(5))
    for(size_t i=0; i<5; i++){
        // Bootstrapping :: q/2 --> q/4
        A[i]      = bitwiseXor(A[i], D[i], 4);
        A[i + 5]  = bitwiseXor(A[i + 5], D[i], 4);
        A[i + 10] = bitwiseXor(A[i + 10], D[i], 4);
        A[i + 15] = bitwiseXor(A[i + 15], D[i], 4);
        A[i + 20] = bitwiseXor(A[i + 20], D[i], 4);
    }
}

void ryo(sha_state& A){
    /**
     * Refference :
     * Table 1.4
     * https://www.cryptotextbook.com/download/Understanding-Cryptography-Keccak.pdf
    */

    rotate_left(A[ 1],  1);
    rotate_left(A[ 2], 62);
    rotate_left(A[ 3], 28);
    rotate_left(A[ 4], 27);
    rotate_left(A[ 5], 36);
    rotate_left(A[ 6], 44);
    rotate_left(A[ 7],  6);
    rotate_left(A[ 8], 55);
    rotate_left(A[ 9], 20);
    rotate_left(A[10],  3);
    rotate_left(A[11], 10);
    rotate_left(A[12], 43);
    rotate_left(A[13], 25);
    rotate_left(A[14], 39);
    rotate_left(A[15], 41);
    rotate_left(A[16], 45);
    rotate_left(A[17], 15);
    rotate_left(A[18], 21);
    rotate_left(A[19],  8);
    rotate_left(A[20], 18);
    rotate_left(A[21],  2);
    rotate_left(A[22], 61);
    rotate_left(A[23], 56);
    rotate_left(A[24], 14);
}

void pi(sha_state& A){
    vec_LWE A1 = A[1];
    A[ 1] = A[ 6], A[ 6] = A[ 9], A[ 9] = A[22], A[22] = A[14],
    A[14] = A[20], A[20] = A[ 2], A[ 2] = A[12], A[12] = A[13],
    A[13] = A[19], A[19] = A[23], A[23] = A[15], A[15] = A[ 4],
    A[ 4] = A[24], A[24] = A[21], A[21] = A[ 8], A[ 8] = A[16],
    A[16] = A[ 5], A[ 5] = A[ 3], A[ 3] = A[18], A[18] = A[17],
    A[17] = A[11], A[11] = A[ 7], A[ 7] = A[10], A[10] = A1;
}

void chi(sha_state& A){
// #pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(5))
    for(size_t i=0; i<25; i+=5){
        /**
         * 주소값을 복사해와 기존 원소에 영향을 줌...!!
        */
        // 2 * CT (XOR), || AND, NOT :: Bootstrapping :: q/4 --> q/2
        // vec_LWE A0 = A[0 + i], A1 = A[1 + i];

        vec_LWE a_0 = create_copy(A[0 + i]), a_1 = create_copy(A[1 + i]), 
                a_2 = create_copy(A[2 + i]), a_3 = create_copy(A[3 + i]), 
                a_4 = create_copy(A[4 + i]);

        vec_LWE A0 = create_copy(A[0 + i]), A1 = create_copy(A[1 + i]);

        // 비효율?
        auto len = a_0[0]->GetA().GetLength();
        auto mod = a_0[0]->GetModulus();
        NativeVector v(len, mod, 2);
        NativeInteger t(2);

        // cout << "어라라? A[0 + i] pt --> " << A[0 + i][0]->GetptModulus().ConvertToInt() << "\n";
        for (size_t j = 0; j < 64; j++){
            a_0[j]->GetA().ModMulEq(v); a_0[j]->GetB().ModMulEq(t, mod); a_0[j]->SetptModulus(t);
            a_1[j]->GetA().ModMulEq(v); a_1[j]->GetB().ModMulEq(t, mod); a_1[j]->SetptModulus(t);
            a_2[j]->GetA().ModMulEq(v); a_2[j]->GetB().ModMulEq(t, mod); a_2[j]->SetptModulus(t);
            a_3[j]->GetA().ModMulEq(v); a_3[j]->GetB().ModMulEq(t, mod); a_3[j]->SetptModulus(t);
            a_4[j]->GetA().ModMulEq(v); a_4[j]->GetB().ModMulEq(t, mod); a_4[j]->SetptModulus(t);
        }
        // cout << "어라라? A[0 + i] pt --> " << A[0 + i][0]->GetptModulus().ConvertToInt() << "\n";

        A[0 + i] = bitwiseXor( a_0, bitwiseAnd( A[2 + i], bitwiseNot(A1)), 2); 
        A[1 + i] = bitwiseXor( a_1, bitwiseAnd( A[3 + i], bitwiseNot(A[2 + i])), 2); 
        A[2 + i] = bitwiseXor( a_2, bitwiseAnd( A[4 + i], bitwiseNot(A[3 + i])), 2); 
        A[3 + i] = bitwiseXor( a_3, bitwiseAnd( A0, bitwiseNot(A[4 + i])), 2); 
        A[4 + i] = bitwiseXor( a_4, bitwiseAnd( A1, bitwiseNot(A0)), 2);
    }


    
}

void iota_v2(sha_state& A, int round){
    vector<int> RoundConstant[24] = {
        {63},
        {48, 56, 62},
        {0, 48, 56, 60, 62},
        {0, 32, 48},
        {48, 56, 60, 62, 63},
        {32, 63}, 
        {0, 32, 48, 56, 63},
        {0, 48, 60, 63},
        {56, 60, 62},
        {56, 60},
        {32, 48, 60, 63},
        {32, 60, 62},
        {32, 48, 56, 60, 62, 63},
        {0, 56, 60, 62, 63},
        {0, 48, 56, 60, 63}, 
        {0, 48, 62, 63}, 
        {0, 48, 62}, 
        {0, 56}, 
        {48, 60, 62}, 
        {0, 32, 60, 62}, 
        {0, 32, 48, 56, 63}, 
        {0, 48, 56}, 
        {32, 63}, 
        {0, 32, 48, 60}
    };

    for (size_t i = 0; i < RoundConstant[round].size(); i++){
        A[0][RoundConstant[round][i]] = cc.EvalNOT_sha3(A[0][RoundConstant[round][i]]);
    }
}

void rounding_Func(sha_state& A){ 
    for(size_t i=0; i<24; i++){
        theta(A);

        cout << "\n\n :: After THETA :: \n\n";
        printState(A, 4);

        ryo(A);

        cout << "\n\n :: After RYO :: \n\n";
        printState(A, 4);

        pi(A);

        cout << "\n\n :: After PI :: \n\n";
        printState(A, 4);

        chi(A);

        cout << "\n\n :: After CHI :: \n\n";
        printState(A, 2);

        iota_v2(A, i);

        cout << "\n\n :: After IOTA :: \n\n";
        printState(A, 2);

        cout << i << "_Round Done\n";
    }
}

param_sha3 ParamGen(string data, ConstLWEPrivateKey sk){
    /**
     * 사용자 구분.
     * CipherText for string
     * Padding Block
     * State h
     * RoundConstant
    */
    param_sha3 param;
    size_t block = 136; // keccak-256

    param.data = data;

    /**
     * For CipherText
     * */    
    param.ct = EncForHash(data, sk);
    
    /**
     * For Padding Block
    */
    param.PaddingBlock = PadBlockGen(sk);

    int len = data.length();
    int modLen = len % block;

    for(size_t i=0; i<(size_t)modLen*8; i++){
        param.PaddingBlock[(block-modLen)*8 + i] = param.ct[i];
    }

    vec_LWE temp = HexaGen("06", sk);
    for(size_t i=0; i<8; i++){
        param.PaddingBlock[(block-modLen-1)*8 + i] = temp[i];
    }

    temp = HexaGen("80", sk);
    for(size_t i=0; i<8; i++){
        param.PaddingBlock[i] = temp[i];
    }
    
    /**
     * For State h
    */
    param.h = stateGen(sk);

    /*print*/
    // cout << "in PARAMGEN :: \n";
    // cout << "param_state's p --> " << param.h[0][0]->GetptModulus().ConvertToInt() << "\n";
    // cout << "param_Padding's p --> " << param.PaddingBlock[0]->GetptModulus().ConvertToInt() << "\n";

    return param;
}

vec_LWE sha_3(param_sha3 param){
    size_t block = 136; // keccak-256

    int len = param.data.size();
    for(int i=1; i <= (int)(len/block); i++){
        MesXOR(param.ct, len*8 - 1088*i, param.h);
    }

    MesXOR(param.PaddingBlock, 0, param.h);

    vec_LWE ANS;
    for(size_t i=0; i<4; i++){
        for(size_t j=0; j<8; j++){
            for(size_t k=0; k<8; k++){
                ANS.push_back(param.h[i][ (7-j)*8 + k ]);
            }
        }
    }

    return ANS;
}