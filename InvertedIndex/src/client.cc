/*
 * This class handles the functions unique to the client
 * For example, querying the data of the server
 */

#include "client.h"
#include "common.h"
#include <iostream>
#include <cmath>
#include <chrono>
#include <fstream>

using namespace std;
using namespace seal;
using namespace seal::util;

Client::Client(string& in_query_csv_file, Encryptor& in_encryptor, 
           Decryptor& in_decryptor, BatchEncoder& in_batch_encoder, Modulus& in_mod,
           size_t in_batch_size, Server& in_server, int in_bytes_to_client,
           const vector<string>& in_headers, const string in_intersection_ids_file)
    : decryptor(in_decryptor), encryptor(in_encryptor),
      batch_encoder(in_batch_encoder), mod(in_mod), batch_size(in_batch_size),
      server(in_server), bytes_to_client(in_bytes_to_client), headers(in_headers),
      intersection_ids_file(in_intersection_ids_file) {
    
    slot_count = batch_encoder.slot_count();
    
    raw_query = load_database_csv(in_query_csv_file, headers);
          
}

uint64_t Client::coprf(const string& input_str, const Modulus& mod) {
    if (sodium_init() == -1) {
        cerr << "libsodium initialization failed" << endl;
        exit(0);
    }

    const unsigned char* input = reinterpret_cast<const unsigned char*>(input_str.data());
    size_t input_len = input_str.size();
    
    // Hash input to a point
    unsigned char A[crypto_core_ristretto255_BYTES];
    hash_to_point(A, input, input_len);

    // Generate blinding scalar r and computes A' = r * A
    unsigned char r[crypto_core_ristretto255_SCALARBYTES];
    generate_random_scalar(r);
    
    unsigned char A_blinded[crypto_core_ristretto255_BYTES];
    if (crypto_scalarmult_ristretto255(A_blinded, r, A) != 0)
        cerr << "The resulting element is the identity element" << endl;
    
    // Compute r^(-1)
    unsigned char r_inv[crypto_core_ristretto255_SCALARBYTES];
    crypto_core_ristretto255_scalar_invert(r_inv, r);

    // Compute C = r^(-1) * C'
    unsigned char C[crypto_core_ristretto255_BYTES];
    unsigned char C_blinded[crypto_core_ristretto255_BYTES];
    server.oprf_to_client(A_blinded, C_blinded);
    bytes_to_client += crypto_core_ristretto255_BYTES; // sizeof C_blinded
    
    if (crypto_scalarmult_ristretto255(C, r_inv, C_blinded) != 0)
        cerr << "The resulting element is the identity element" << endl;
    
    // Derive the final OPRF output
    uint64_t final_output = derive_oprf_output(C, mod.value());

    return final_output;
   
}

// Transforms the queries into polynomials
vector<vector<uint64_t>> Client::query_transform(const vector<vector<pair<string, string>>>& query, const Modulus& mod) {
    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    vector<vector<pair<uint64_t, uint64_t>>> result;
    
    // For each query
    for (auto &record : query) {
        vector<pair<uint64_t, uint64_t>> temp_result;
        // For each (a,v) pair in a query
        for (const auto &[attr, val] : record) {
            // Encode the strings so that they can be used to interpolate a polynomial
            uint64_t attr_hash = encode_symbol(attr, mod);
            uint64_t val_hash = coprf(val, mod);
            temp_result.emplace_back(attr_hash, val_hash);
        }
        result.push_back(temp_result);
    }
    
    vector<vector<uint64_t>> polynomial = database_poly(result, mod);
    
    chrono::steady_clock::time_point end = chrono::steady_clock::now();
    cout << "Time for Client query transform (incl. OPRF) = " << chrono::duration_cast<chrono::microseconds>(end - begin).count()/60000000.0 << "[min]" << endl;
    
    return polynomial;
}

bool Client::init_queries() {
    if (raw_query.size() == 0) return false;
    query_coeffs = query_transform(raw_query, mod);
    return true;
}

// Send the number of queries (|Y|)
int Client::get_nr_queries() {
    return query_coeffs.size();
}

// Return the number of bytes sent to the client
int Client::get_bytes_to_client() {
    return bytes_to_client;
}

// Horner's method to evaluate polynomials (O(n))
uint64_t Client::evaluate_polynomial(const vector<uint64_t> &coeffs, int x, Modulus mod) {
    uint64_t result = 0;
    for (int i = coeffs.size() - 1; i >= 0; i--) {
        result = add_uint_mod(multiply_uint_mod(result, x, mod), coeffs[i], mod);
    }
    return result;
}

// Run the 
void Client::run() {
    int q_count = 0, match_count = 0;
    vector<int64_t> modulo_poly_eval = server.get_modulo_poly_eval();
    vector<int64_t> coeff_length = server.get_coeff_length();
    int nr_records = server.get_nr_records();
    int nr_batches = floor(nr_records/batch_size);
    nr_batches += (nr_records % batch_size > 0) ? 1 : 0;
    bytes_to_client += sizeof(nr_batches) + modulo_poly_eval.size() * sizeof(int64_t) + coeff_length.size() *  sizeof(int64_t);
    
    ofstream out_file(intersection_ids_file);
    
    // For each query
    for (vector<uint64_t> final_coeffs_query : query_coeffs) {
        // Encrypt the query coefficients
        final_coeffs_query.resize(slot_count, 0);
        Ciphertext cts_coeffs;
        Plaintext plain_query;
        batch_encoder.encode(final_coeffs_query, plain_query);
        encryptor.encrypt(plain_query, cts_coeffs);

        // Get the attributes present in the query and encode them
        vector<uint64_t> attribute_values;
        for (const auto& p : raw_query[q_count]) {
            attribute_values.push_back(encode_symbol(p.first, mod));
        }
        
        vector<Ciphertext> attributes;
        Ciphertext prev_attr;
        int64_t prev_cl = 0;         
                
        // Looping per batch is necessary as coeff_length might not be the same for all batches
        // Even better would be to remember all coeff_lengths already done and reuse them to ensure a computation is done only once
        for (size_t k = 0; k < nr_batches; k++) {
            if (coeff_length[k] == prev_cl) {
                attributes.push_back(prev_attr);
                continue;
            }
        
            // Results in v_b (a^0, a^1, a^2, ..., a^o) where all exponents are in mod l
            vector<vector<uint64_t>> attr;
            for (size_t i = 0; i < attribute_values.size(); i++) {
                vector<uint64_t> attribute;
                for (size_t j = 0; j < coeff_length[k]; j++) {
                    uint64_t temp = exponentiate_uint_mod(attribute_values[i], j % modulo_poly_eval[k], mod);
                    attribute.push_back(temp);
                }
                attr.push_back(attribute);
            }
            
            
            // Blinding the attributes
            vector<uint64_t> rnd_vec = random_vector(attribute_values.size(), mod.value());
            vector<uint64_t> res_vec;
            for (size_t i = 0; i < coeff_length[k]; i++) {
                uint64_t result = 0;
                for (size_t j = 0; j < attribute_values.size(); j++) {
                    uint64_t tmp = multiply_uint_mod(rnd_vec[j], attr[j][i], mod);
                    result = add_uint_mod(result, tmp, mod);
                }
                res_vec.push_back(result);
            }
            // Encrypt the attributes
            Plaintext attr_pt;
            Ciphertext attr_ct;
            batch_encoder.encode(res_vec, attr_pt);
            encryptor.encrypt(attr_pt, attr_ct);
            
            attributes.push_back(attr_ct);
            prev_attr = attr_ct;
            prev_cl = coeff_length[k];
        }
        
        // Send the enrypted query and attributes to the server and get the output 
        auto batch_cts = server.process_query(cts_coeffs, attributes);
        bytes_to_client += batch_cts.size() * sizeof(Ciphertext);
        
        // Decrypt the results
        vector<vector<uint64_t>> result;
        for (const auto& bc : batch_cts) {
            vector<uint64_t> r;
            Plaintext plain_result;
            decryptor.decrypt(bc, plain_result);
            batch_encoder.decode(plain_result, r);
            result.push_back(r);
        }
        
        // The server filled in one of the variables, so the polynomial can be simplified
        vector<vector<uint64_t>> simplified_result;
        for (size_t j = 0; j < result.size(); j++) {
            vector<uint64_t> sr(int(coeff_length[j]/modulo_poly_eval[j]), 0);
            
            // Sum all coefficients with the same exponent
            for (size_t i = 0; i < coeff_length[j]; i++) { 
                sr[int(i/modulo_poly_eval[j])] = add_uint_mod(sr[int(i/modulo_poly_eval[j])],
                                                              result[j][i], mod);
            }
            
            simplified_result.push_back(sr);
        }
        
        // Evaluate each polynomial for all possible indexes
        // This assumes that the polynomials in simplified_result are in order
        bool matches = false;
        for (size_t j = 0; j < simplified_result.size(); j++) {
            for (size_t i = 1; i <= batch_size; i++) {
                if (i+batch_size*j > nr_records) break;
                uint64_t final_result = evaluate_polynomial(simplified_result[j], i, mod);
                if (final_result == 0) {
                    // The actual record number
                    out_file << i+batch_size*j << ",";
                    // Add the IoC on which it matched
                    for (const auto& p : raw_query[q_count]) {
                        out_file << p.first << " " << p.second << ",";
                    }
                    out_file << endl;
                    matches = true;
                    match_count++;
                }
            }
        }
    q_count++;
    }
    cout << match_count << " matches!" << endl;
}
