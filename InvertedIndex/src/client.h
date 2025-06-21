#pragma once
#include "seal/seal.h"
#include "server.h"
#include <sodium.h>

class Client {
public:
    Client(std::string& in_query_csv_file, seal::Encryptor& in_encryptor, 
           seal::Decryptor& in_decryptor, seal::BatchEncoder& in_batch_encoder, 
           seal::Modulus& in_mod, size_t in_batch_size, Server& in_server,
           int in_bytes_to_client, const std::vector<std::string>& in_headers,
           const std::string in_intersection_ids_file);
           
   bool init_queries();
   int get_bytes_to_client();
   int get_nr_queries();
   uint64_t coprf(const std::string& input_str, const seal::Modulus& mod);
   std::vector<std::vector<uint64_t>> query_transform(const std::vector<std::vector<std::pair<std::string, std::string>>>& query, const seal::Modulus& mod);
   void run();
   uint64_t evaluate_polynomial(const std::vector<uint64_t> &coeffs, int x, seal::Modulus mod);
    
private:
    seal::Encryptor& encryptor;
    seal::Decryptor& decryptor;
    seal::BatchEncoder& batch_encoder;
    seal::Modulus& mod;
    Server& server;
    
    std::vector<std::vector<std::pair<std::string, std::string>>> raw_query;
    std::vector<std::vector<uint64_t>> query_coeffs;
    std::string intersection_ids_file;
    const std::vector<std::string>& headers;
    size_t batch_size;
    int slot_count;
    int bytes_to_client;
};
