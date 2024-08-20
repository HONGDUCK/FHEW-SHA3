#include "sha3-overlap.h"

int u_mod_O(int x, int modN){
    if(x % modN >= 0 ){
        return x % modN;
    }else{
        return modN + (x % modN);
    }
}
void rotate_left_O(vec_LWE& ct, size_t index){
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
vec_LWE temp_rotate_left_O(vec_LWE ct, size_t index){
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
vec_LWE EncForHash_O(string data, ConstLWEPrivateKey sk, BinFHEContext cc){
    vec_LWE temp;
    size_t len = data.size();

    for(int i=len-1; i>=0; i--){
        bitset<8> b( (char)data[i] );
        for(int j=b.size()-1; j>=0; j--){
            auto ct = cc.Encrypt(sk, b[j], SMALL_DIM, 2);
            temp.push_back(ct);
        }
    }

    return temp;
}
vec_LWE PadBlockGen_O(ConstLWEPrivateKey sk, BinFHEContext cc){
    vec_LWE temp;
    for(size_t i=0; i<1088; i++){
        temp.push_back(cc.Encrypt(sk, 0, SMALL_DIM, 2));
    }

    return temp;
}
vec_LWE HexaGen_O(string hexa, ConstLWEPrivateKey sk, BinFHEContext cc){
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
sha_state stateGen_O(ConstLWEPrivateKey sk, BinFHEContext cc){
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

vec_LWE SHA3_OverLap::bitwiseXor_Add(vec_LWE ct1, vec_LWE ct2){
    vec_LWE temp;
    size_t ctLen = ct1.size(); // 64bit

    for(size_t i=0; i<ctLen; i++){
        LWECiphertext ctTemp = make_shared<LWECiphertextImpl>(*ct1[i]);
        ctTemp->SetptModulus(ct1[i]->GetptModulus());
        ctTemp->SetA(ct1[i]->GetA().ModAdd(ct2[i]->GetA()));
        ctTemp->SetB(ct1[i]->GetB().Add(ct2[i]->GetB()));

        temp.push_back(ctTemp);
    }

    return temp;
}
vec_LWE SHA3_OverLap::bitwiseNot(vec_LWE ct1){
    // for 4/q
    vec_LWE temp;
    size_t ctLen = ct1.size();

    for(size_t i=0; i<ctLen; i++){
        temp.push_back(cc.EvalNOT(ct1[i]));
    }

    return temp;
}
vec_LWE SHA3_OverLap::bitwiseAnd(vec_LWE ct1, vec_LWE ct2){
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
vec_LWE SHA3_OverLap::create_copy(vec_LWE const &vec){
    vec_LWE v;
    for (size_t i = 0; i < vec.size(); i++){
        auto ct = cc.EvalNOT(vec[i]);
        ct = cc.EvalNOT(ct);

        v.push_back(ct);
    }

    return v;
}
void SHA3_OverLap::blindrotation_state(sha_state& A, PlaintextModulus p){
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(this->number_of_thread))
    for(size_t i=0; i<A.size(); i++){
        for(size_t j=0; j<A[i].size(); j++){
            A[i][j] = cc.EvalBinGate_overlap(XOR, A[i][j], p);
        }
    }
}
void SHA3_OverLap::MKMSwitch_state(sha_state& A, PlaintextModulus p){
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(this->number_of_thread))
    for(size_t i=0; i<A.size(); i++){
        for(size_t j=0; j<A[i].size(); j++){
            A[i][j] = cc.MKMSwitch_overlap(A[i][j], p);
        }
    }
}
void SHA3_OverLap::printstate(PlaintextModulus p, LWEPrivateKey sk){
    for(int i=0; i<=16; i++){
        cout << "h[" << i << "] : ";

        LWEPlaintext res;
        for(int j=0; j<64; j++){
            if(j % 8 == 0) cout << " ";
            cc.Decrypt(sk, H[i][j], &res, p);
            cout << res;
        }

        cout << "\n";
    }    
}
void SHA3_OverLap::printdigest(PlaintextModulus p, LWEPrivateKey sk){
    vector<LWEPlaintext> ans;
    for(size_t i=0; i<this->digest.size(); i++){
        LWEPlaintext res;
        cc.Decrypt(sk, this->digest[i], &res, 2);
        ans.push_back(res);
    }
    for(size_t i=0; i<ans.size(); i++){
        if(i % 8 == 0) cout << " ";
        if(i % 16 == 0) cout << "\n";

        cout << ans[i];
    }
    cout << "\n";
}

void SHA3_OverLap::theta(){
    sha_state C(5);
    sha_state D(5);

    // C[x] = A[x,0] ⊕ A[x,1] ⊕ A[x,2] ⊕ A[x,3] ⊕ A[x,4]
    for(size_t i=0; i<5; i++){
        C[i] = bitwiseXor_Add( H[i +  0],
               bitwiseXor_Add( H[i +  5],
               bitwiseXor_Add( H[i + 10], 
               bitwiseXor_Add( H[i + 15], H[i + 20]))));
    }

    this->blindrotation_state(C, 2);
    this->MKMSwitch_state(C, 2);        // Problem!!


    // D[x] = C[x−1] ⊕ rotation(C[x+1],1) in Z_q
    for(size_t i=0; i<5; i++){
        D[i] = bitwiseXor_Add( C[u_mod_O(i-1, 5)], temp_rotate_left_O(C[u_mod_O(i+1, 5)],1)); 
    }

    // A[x,y] = A[x,y] ⊕ D[x]
    for(size_t i=0; i<5; i++){
        // Bootstrapping :: q/2 --> q/4
        H[i]      = bitwiseXor_Add(H[i],      D[i]);
        H[i + 5]  = bitwiseXor_Add(H[i + 5],  D[i]);
        H[i + 10] = bitwiseXor_Add(H[i + 10], D[i]);
        H[i + 15] = bitwiseXor_Add(H[i + 15], D[i]);
        H[i + 20] = bitwiseXor_Add(H[i + 20], D[i]);
    }

    this->blindrotation_state(H, 4);
    this->MKMSwitch_state(H, 4);
}
void SHA3_OverLap::rho(){
    rotate_left_O(H[ 1],  1);
    rotate_left_O(H[ 2], 62);
    rotate_left_O(H[ 3], 28);
    rotate_left_O(H[ 4], 27);
    rotate_left_O(H[ 5], 36);
    rotate_left_O(H[ 6], 44);
    rotate_left_O(H[ 7],  6);
    rotate_left_O(H[ 8], 55);
    rotate_left_O(H[ 9], 20);
    rotate_left_O(H[10],  3);
    rotate_left_O(H[11], 10);
    rotate_left_O(H[12], 43);
    rotate_left_O(H[13], 25);
    rotate_left_O(H[14], 39);
    rotate_left_O(H[15], 41);
    rotate_left_O(H[16], 45);
    rotate_left_O(H[17], 15);
    rotate_left_O(H[18], 21);
    rotate_left_O(H[19],  8);
    rotate_left_O(H[20], 18);
    rotate_left_O(H[21],  2);
    rotate_left_O(H[22], 61);
    rotate_left_O(H[23], 56);
    rotate_left_O(H[24], 14);
}
void SHA3_OverLap::pi(){
    vec_LWE H1 = H[1];
    H[ 1] = H[ 6], H[ 6] = H[ 9], H[ 9] = H[22], H[22] = H[14],
    H[14] = H[20], H[20] = H[ 2], H[ 2] = H[12], H[12] = H[13],
    H[13] = H[19], H[19] = H[23], H[23] = H[15], H[15] = H[ 4],
    H[ 4] = H[24], H[24] = H[21], H[21] = H[ 8], H[ 8] = H[16],
    H[16] = H[ 5], H[ 5] = H[ 3], H[ 3] = H[18], H[18] = H[17],
    H[17] = H[11], H[11] = H[ 7], H[ 7] = H[10], H[10] = H1;
}
void SHA3_OverLap::chi(){
    for(size_t i=0; i<25; i+=5){
        vec_LWE a_0 = create_copy(H[0 + i]), a_1 = create_copy(H[1 + i]), 
                a_2 = create_copy(H[2 + i]), a_3 = create_copy(H[3 + i]), 
                a_4 = create_copy(H[4 + i]);

        vec_LWE A0 = create_copy(H[0 + i]), A1 = create_copy(H[1 + i]);

        // 비효율?
        auto len = a_0[0]->GetA().GetLength();
        auto mod = a_0[0]->GetModulus();
        NativeVector v(len, mod, 2);
        NativeInteger t(2);

        for (size_t j = 0; j < 64; j++){
            a_0[j]->GetA().ModMulEq(v); a_0[j]->GetB().ModMulEq(t, mod); a_0[j]->SetptModulus(t);
            a_1[j]->GetA().ModMulEq(v); a_1[j]->GetB().ModMulEq(t, mod); a_1[j]->SetptModulus(t);
            a_2[j]->GetA().ModMulEq(v); a_2[j]->GetB().ModMulEq(t, mod); a_2[j]->SetptModulus(t);
            a_3[j]->GetA().ModMulEq(v); a_3[j]->GetB().ModMulEq(t, mod); a_3[j]->SetptModulus(t);
            a_4[j]->GetA().ModMulEq(v); a_4[j]->GetB().ModMulEq(t, mod); a_4[j]->SetptModulus(t);
        }

        H[0 + i] = bitwiseXor_Add( a_0, bitwiseAnd( H[2 + i], bitwiseNot(A1))      ); 
        H[1 + i] = bitwiseXor_Add( a_1, bitwiseAnd( H[3 + i], bitwiseNot(H[2 + i]))); 
        H[2 + i] = bitwiseXor_Add( a_2, bitwiseAnd( H[4 + i], bitwiseNot(H[3 + i]))); 
        H[3 + i] = bitwiseXor_Add( a_3, bitwiseAnd( A0,       bitwiseNot(H[4 + i]))); 
        H[4 + i] = bitwiseXor_Add( a_4, bitwiseAnd( A1,       bitwiseNot(A0))      );

    }
    this->blindrotation_state(H, 2);
    this->MKMSwitch_state(H,2);
}
void SHA3_OverLap::iota(int round){
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
        H[0][RoundConstant[round][i]] = cc.EvalNOT_sha3(H[0][RoundConstant[round][i]]);
    }
}

void SHA3_OverLap::state_gen(string data, ConstLWEPrivateKey sk){
    size_t block = 136; // for keccak-256
    this->data = data;
    this->ctxt = EncForHash_O(data, sk, cc);
    this->PaddingBlock = PadBlockGen_O(sk, cc);

    int len = data.length();
    int modLen = len % block;

    for(size_t i=0; i<(size_t)modLen*8; i++){
        this->PaddingBlock[(block-modLen)*8 + i] = this->ctxt[i];
    }

    vec_LWE temp = HexaGen_O("06", sk, cc);
    for(size_t i=0; i<8; i++){
        this->PaddingBlock[(block-modLen-1)*8 + i] = temp[i];
    }

    temp = HexaGen_O("80", sk, cc);
    for(size_t i=0; i<8; i++){
        this->PaddingBlock[i] = temp[i];
    }

    this->H = stateGen_O(sk, cc);
}
void SHA3_OverLap::round_function(){
    for(size_t i=0; i<24; i++){
        this->theta();
        // cout << "After Theta\n";
        // printstate(4, sk);
        this->rho();
        // cout << "After rho\n";
        // printstate(4, sk);        
        this->pi();
        // cout << "After pi\n";
        // printstate(4, sk);
        this->chi();
        // cout << "After chi\n";
        // printstate(2, sk);
        this->iota(i);
        // cout << "After iota\n";
        // printstate(2, sk);
    }
}
void SHA3_OverLap::building_hash(vec_LWE ct, size_t start_index){
    /**
     * 17 * 64 --> 1088
     * keccak-256
    */
    for(int i=16; i>=0; i--){
        vec_LWE temp;
        for(size_t j=0; j<64; j++){
            temp.push_back(ct[(int)((int)start_index + (16-i)*64) + j]);
        }

        this->H[i] = bitwiseXor_Add(temp, this->H[i]); // point-wise NOT 으로 변경.
    }

    this->round_function();
}
void SHA3_OverLap::build_hash(){
    size_t block = 136; // keccak-256

    int len = this->data.size();
    for(int i=1; i <= (int)(len/block); i++){
        building_hash(this->ctxt, len*8 - 1088*i);
    }

    building_hash(this->PaddingBlock, 0);

    for(size_t i=0; i<4; i++){
        for(size_t j=0; j<8; j++){
            for(size_t k=0; k<8; k++){
                this->digest.push_back(this->H[i][ (7-j)*8 + k ]);
            }
        }
    }
}