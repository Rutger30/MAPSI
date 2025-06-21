/*
 * This class handles the functions unique to the server
 * For example, processing a query
 */

#include "server.h"
#include "common.h"
#include <chrono>

using namespace std;
using namespace seal;
using namespace seal::util;

Server::Server(string& in_database_csv_file, Encryptor& in_encryptor, 
               Evaluator& in_evaluator, BatchEncoder& in_batch_encoder,
               Modulus& in_mod, size_t in_batch_size, size_t in_poly_modulus_degree,
               int in_bytes_to_server, const vector<string>& in_headers)
    : encryptor(in_encryptor), evaluator(in_evaluator), 
      batch_encoder(in_batch_encoder), mod(in_mod), batch_size(in_batch_size),
      poly_modulus_degree(in_poly_modulus_degree), bytes_to_server(in_bytes_to_server),
      headers(in_headers) {

    slot_count = batch_encoder.slot_count(); 
    raw_database = load_database_csv(in_database_csv_file, headers);
    nr_records = raw_database.size();
    
    generate_random_scalar(server_key);
    
}

// The server can compute all OPRF values without interaction
uint64_t Server::oprf(const string& input_str, const Modulus& mod) {
    if (sodium_init() == -1) {
        cerr << "libsodium initialization failed" << endl;
        exit(0);
    }

    const unsigned char* input = reinterpret_cast<const unsigned char*>(input_str.data());
    size_t input_len = input_str.size();
    
    // Hash input to a point
    unsigned char A[crypto_core_ristretto255_BYTES];
    hash_to_point(A, input, input_len);
    unsigned char C[crypto_core_ristretto255_BYTES];
    if (crypto_scalarmult_ristretto255(C, server_key, A) != 0)
        cerr << "The resulting element is the identity element" << endl;
    
    uint64_t final_output = derive_oprf_output(C, mod.value());

    return final_output;
}

// Transform the database into polynomials
vector<vector<uint64_t>> Server::database_transform(const vector<vector<pair<string, string>>>& database, const Modulus& mod) {
    vector<vector<pair<uint64_t, uint64_t>>> result;
    for (const auto& record : database) {
        vector<pair<uint64_t, uint64_t>> temp_result;
        for (const auto& [attr, val] : record) {
            uint64_t attr_hash = encode_symbol(attr, mod);
            uint64_t val_hash = oprf(val, mod);
            temp_result.emplace_back(attr_hash, val_hash);
        }
        result.push_back(temp_result);
    }
    
    vector<vector<uint64_t>> polynomial = database_poly(result, mod);
    
    return polynomial;
}

// Compute C' = k * A' for the interactive OPRF with the client
void Server::oprf_to_client(const unsigned char* A_blinded, unsigned char* C_blinded) {
    bytes_to_server += crypto_core_ristretto255_BYTES; // sizeof A_blinded
    if (crypto_scalarmult_ristretto255(C_blinded, server_key, A_blinded) != 0)
        cerr << "The resulting element is the identity element" << endl;
}

// Initialise the database (transform the database and interpolate it to a bivariate polynomial
bool Server::init_database() {
    chrono::steady_clock::time_point dt_begin = chrono::steady_clock::now();
    vector<vector<uint64_t>> database_coeffs = database_transform(raw_database, mod);
    
    // This code does not support multiple ciphertexts per batch/cluster
    if ((raw_database.size() == 0) || (batch_size*find_largest_vector(database_coeffs) > poly_modulus_degree)) {
        cout << "The poly modulus degree should be larger than the batch_size * number of attributes so that all coefficients fit in one ciphertext" << endl;
        cout << "Currently pmd: " << poly_modulus_degree << ", batch_size: " << batch_size << ", #attributes: " << find_largest_vector(database_coeffs) << endl;
        return false;
    }
    
    nr_batches = floor(nr_records/batch_size);
    int remainder = nr_records%batch_size;
    
    vector<vector<uint64_t>> batch_lagrange;
    chrono::steady_clock::time_point l_begin = chrono::steady_clock::now();
    cout << "Time for database transform with raw database size " << raw_database.size() << " = " << chrono::duration_cast<chrono::microseconds>(l_begin - dt_begin).count()/60000000.0 << "[min]" << endl;
    
    // Compute the batch-sized polynomial if there is at least one full batch
    if (nr_batches >= 1) batch_lagrange = init_lagrangeset(batch_size, mod); 
    
    chrono::steady_clock::time_point l_end = chrono::steady_clock::now();
    cout << "Time for lagrange on " << batch_size << " points = " << chrono::duration_cast<chrono::microseconds>(l_end - l_begin).count()/60000000.0 << "[min]" << endl;
            
    // Interpolate the record polynomials with the batch polynomials into a bivariate polynomial
    vector<vector<uint64_t>> final_coeffs_database;    
    for (size_t i = 0; i < nr_batches; i++) {
//        cout << (i+1)*batch_size << endl;
        vector<vector<uint64_t>> database_coeffs_batch(database_coeffs.begin()+i*batch_size,
                                                       database_coeffs.begin()+(i+1)*batch_size);
        modulo_poly_eval.push_back(find_largest_vector(database_coeffs_batch));
        final_coeffs_database.emplace_back(interpolate(batch_lagrange, database_coeffs_batch, mod));
        coeff_length.push_back(final_coeffs_database[i].size());
    }

    // If the batch-size is not a divisor of the number of records, handle the remainder  
    vector<vector<uint64_t>> rest_lagrange;
    if (remainder > 0) {
        chrono::steady_clock::time_point r_begin = chrono::steady_clock::now();
        cout << "Remainder: " << remainder << endl;
        rest_lagrange = init_lagrangeset(remainder, mod);
        vector<vector<uint64_t>> database_coeffs_rest(database_coeffs.end()-remainder, database_coeffs.end());
        final_coeffs_database.emplace_back(interpolate(rest_lagrange, database_coeffs_rest, mod));
        modulo_poly_eval.push_back(find_largest_vector(database_coeffs_rest));
        coeff_length.push_back(final_coeffs_database[nr_batches].size());
        nr_batches++;
        chrono::steady_clock::time_point r_end = chrono::steady_clock::now();
        cout << "Time for lagrange on " << remainder << " points = " << chrono::duration_cast<chrono::microseconds>(r_end - r_begin).count()/60000000.0 << "[min]" << endl;
    }
    
    // Encode the database coefficients into plaintexts
    for (const auto& db_coeffs : final_coeffs_database) {
        Plaintext db_pt;
        batch_encoder.encode(db_coeffs, db_pt);
        database_pts.push_back(db_pt);
    }
    
    return true;
}

// Initialise the polynomial based on the (index, 0/1) points
vector<vector<uint64_t>> Server::init_lagrangeset(int64_t nr_records, Modulus mod) {
    vector<vector<pair<uint64_t, uint64_t>>> lagrange_points;

    for (size_t i = 1; i <= nr_records; i++) {
        vector<pair<uint64_t, uint64_t>> temp;
        for (size_t j = 1; j <= nr_records; j++) {
            if (i == j) {
                temp.emplace_back(j, 1);
            }
            else {
                temp.emplace_back(j, 0);
            }
        }
        lagrange_points.push_back(temp);
    }
    return database_poly(lagrange_points, mod);
}

// Interpolate two polynomials
vector<uint64_t> Server::interpolate(vector<vector<uint64_t>> lagrange, vector<vector<uint64_t>> dataset, Modulus mod) {
    uint64_t nr_attr = find_largest_vector(dataset);
    vector<uint64_t> final_coeffs(find_largest_vector(lagrange)*nr_attr, 0);
    
    // The vector becomes x^0y^0, x^0y^1, x^0y^2, ..., x^1y^0, etc.
    for (size_t i = 0; i < lagrange.size(); i++) {
        for (size_t j = 0; j < lagrange[i].size(); j++) {
            for (size_t k = 0; k < dataset[i].size(); k++) {
                final_coeffs[j*nr_attr+k] = add_uint_mod(
                                                final_coeffs[j*nr_attr+k],
                                                multiply_uint_mod(
                                                    dataset[i][k],
                                                    lagrange[i][j], 
                                                    mod),
                                                mod); 
            }
        }
    }
    return final_coeffs;
}

// Process the query sent by the client
vector<Ciphertext> Server::process_query(const Ciphertext& query, const vector<Ciphertext>& attributes) {
    bytes_to_server += sizeof(query) + attributes.size() * sizeof(Ciphertext);
    vector<Ciphertext> results;
    // Compute D(i,j) - Q(j)
    for (size_t i = 0; i < database_pts.size(); i++) {
        Ciphertext tmp;
        evaluator.sub_plain(query, database_pts[i], tmp);
        results.push_back(tmp);
    }
    
    // Both database_pts and attributes are the same size (nr_records/batch_size)
    for (size_t i = 0; i < attributes.size(); i++) {
        Plaintext scalar;
        evaluator.multiply_inplace(results[i], attributes[i]);
        
        // Blinding with random scalar
        vector<uint64_t> rnd_scalar(slot_count, random_scalar(mod.value()));
        batch_encoder.encode(rnd_scalar, scalar);
        evaluator.multiply_plain_inplace(results[i], scalar);
    }
    
    return results;
}

// Return the number of records (|X|)
int Server::get_nr_records() {
    return nr_records;
}

// Return the bytes sent to the server
int Server::get_bytes_to_server() {
    return bytes_to_server;
}

// Return the vector containing the size of the larger polynomial per batch/cluster
vector<int64_t> Server::get_modulo_poly_eval() {
    return modulo_poly_eval;
}

// Return the vector containing the size of the bivariate polynomial per batch/cluster
vector<int64_t> Server::get_coeff_length() {
    return coeff_length;
}
      







