#include "binfhecontext.h"
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <bitset>
using namespace std;
using namespace lbcrypto;

#ifndef SHA3_H
#define SHA3_H

typedef vector<LWECiphertext> vec_LWE;
typedef vector<vec_LWE> sha_state;

class SHA3{
public:
    /**
     * @param ct1 ciphertext(vector) that encrypt lane data
     * @param ct2 ciphertext(vector) that encrypt lane data
     * @param p plaintext modulus(scaling factor) after bootstrapping
     * 
     * @return ciphertext that encrypt lane data(ct1 xor ct2) with plaintext modulus p
     */
    vec_LWE bitwiseXor(vec_LWE ct1, vec_LWE ct2, PlaintextModulus p);

    /**
     * @param ct1 ciphertext(vector) that encrypt lane data
     * 
     * @return ciphertext that encrypt lane data(!ct1)
     */
    vec_LWE bitwiseNot(vec_LWE ct1);


    /**
     * @param ct1 ciphertext(vector) that encrypt lane data
     * @param ct2 ciphertext(vector) that encrypt lane data
     * @param p plaintext modulus(scaling factor) after bootstrapping
     * 
     * @return ciphertext that encrypt lane data(ct1 xor ct2) with plaintext modulus 2
     */
    vec_LWE bitwiseAnd(vec_LWE ct1, vec_LWE ct2);

    /**
     * @param vec ciphertext(vector) that encrypt lane data 
     * 
     * @return copy of vec
     */
    vec_LWE create_copy(vec_LWE const &vec); // 수정 필요함


    /**
     * For utility.
     * @param p Plaintext modulus which used in decryption
     * @param sk secret key to decrypt ciphertexts
     * 
     * @return Print current state H
     */
    void printstate(PlaintextModulus p, LWEPrivateKey sk);

    /**
     * For utility.
     * @param p Plaintext modulus which used in decryption
     * @param sk secret key to decrypt ciphertexts
     * 
     * @return Print digest.
     */
    void printdigest(PlaintextModulus p, LWEPrivateKey sk);

    /**
     * Theta step.
     * Perform the theta step on the current state H.
     */
    void theta();
    
    /**
     * Rho step.
     * Perform the rho step on the current state H.
     */
    void rho();

    /**
     * Pi step.
     * Perform the pi step on the current state H.
     */

    void pi();

    /**
     * Chi step.
     * Perform the chi step on the current state H.
     */
    void chi();

    /**
     * Iota step.
     * Perform the iota step on the current state H.
     */
    void iota(int round);
    
    /**
     * Total length of sha3 state - 1600bits
     * 5 * 5 * 64
     * -------------- 5 * 5 ----------------
     *           13 14 10 11 12 
     *           08 09 05 06 07
     *           03 04 00 01 02
     *           23 24 20 21 22
     *           18 19 15 16 17
     * -------------------------------------
     * 
     * @param data Input of sha3
     * @param sk secret key
    */
    void state_gen(string data, ConstLWEPrivateKey sk);

    /**
     * Round function that include 5 steps (theta, pi, rho, chi, iota)
     * To hash a 1600-bit message, the five steps within the rounding function must be repeated a total of 24 times.
     */
    void round_function();

    /**
     * SPONGE Construction
     * Message XOR -> Round function
     */
    void building_hash(vec_LWE ct, size_t start_index);

    /**
     * Interface
     */
    void build_hash();

    /**
     * Initialize BinFHEContext
     */
    void init(BinFHEContext cc){
        this->cc = cc;
    }
    
    /**
     * Set number of thread using calculation
     * Default value is 1
     */
    void set_multi_threads(int num){
        this->number_of_thread = num;
    }

private:
    /**
     * Message
     */
    string data;

    /**
     * Encrypted message
     */
    vec_LWE ctxt;

    /**
     * Padding Block
     */
    vec_LWE PaddingBlock;

    /**
     * Digest(Hashed value)
     */
    vec_LWE digest;

    /**
     * Current state H
     */
    sha_state H;

    /**
     * Number of threads
     * Default : 1
     */
    int number_of_thread = 1;

    BinFHEContext cc;
};

#endif // SHA3_H