#pragma once
#include "seal/seal.h"
#include <vector>
#include <string>
#include <sodium.h>

class Server {
public:
    Server(std::string& in_database_csv_file, seal::Encryptor& in_encryptor, 
           seal::Evaluator& in_evaluator, seal::BatchEncoder& in_batch_encoder,
           seal::Modulus& in_mod, size_t in_batch_size, size_t in_poly_modulus_degree,
           int in_bytes_to_server, const std::vector<std::string>& in_headers);
           
    bool init_database();
    std::vector<std::vector<uint64_t>> database_transform(const std::vector<std::vector<std::pair<std::string, std::string>>>& database, const seal::Modulus& mod);
    uint64_t oprf(const std::string& input_str, const seal::Modulus& mod);
    void oprf_to_client(const unsigned char* A_blinded, unsigned char* C_blinded);
    std::vector<std::vector<uint64_t>> init_lagrangeset(int64_t nr_records, seal::Modulus mod);
    std::vector<uint64_t> interpolate(std::vector<std::vector<uint64_t>> lagrange, std::vector<std::vector<uint64_t>> dataset, seal::Modulus mod);
    std::vector<seal::Ciphertext> process_query(const seal::Ciphertext& query, const std::vector<seal::Ciphertext>& attributes);
    int get_nr_records();
    int get_bytes_to_server();
    std::vector<int64_t> get_modulo_poly_eval();
    std::vector<int64_t> get_coeff_length();
    

private:
    seal::Encryptor& encryptor;
    seal::Evaluator& evaluator;
    seal::BatchEncoder& batch_encoder;
    seal::Modulus& mod;
    
    int slot_count;
    int nr_batches; // Number of Clusters
    int bytes_to_server;
    size_t poly_modulus_degree;
    size_t batch_size; // Cluster size
    size_t nr_records;
    std::vector<std::vector<std::pair<std::string, std::string>>> raw_database;
    std::vector<seal::Plaintext> database_pts;
    std::vector<int64_t> modulo_poly_eval;
    std::vector<int64_t> coeff_length;
    const std::vector<std::string>& headers;
    unsigned char server_key[crypto_core_ristretto255_SCALARBYTES]; // OPRF key
};

