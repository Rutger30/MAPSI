/*
 * This file is used to construct the client and the server
 * It will also output the time used for the protocol and the bytes sent
 */

#include "seal/seal.h"
#include "server.h"
#include "client.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <chrono>

using namespace std;
using namespace seal;

// Load the column names used in the intersection from the specified file
vector<string> load_column_ids(const string &filename) {
    ifstream file(filename);
    string line;
    vector<string> headers;
    
    if (!file.is_open()) {
        cerr << "Failed to open CSV file: " << filename << endl;
        return headers;
    }

    if (getline(file, line)) {
        stringstream ss(line);
        string header;
        while (getline(ss, header, ',')) {
            headers.push_back(header);
        }
    }

    return headers;
}

int main(int argc, char *argv[]) {
    if (argc != 8) {
        cerr << "Usage: " << argv[0] << " <database_csv> <query_csv> <output_csv> <column_ids_csv> <batch_size> <poly_modulus_degree> <plain_modulus_power>" << endl;
        cerr << "Make sure that the <poly_modulus_degree> is larger than the <batch_size> times the maximum number of attributes" << endl;
        // e.g. ./PrivateDatabaseQuery ../../Data/NetworkData50k.csv ../../Data/IoC.csv ../../Data/intersection_ids.csv ../../AttributesNF-UQ-NIDS-v2_columns6.csv 1000 8192 24
        return 1;
    }
    
    size_t bytes_to_server = 0;
    size_t bytes_to_client = 0;
    
    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    
    string database_csv_file = argv[1];
    string query_csv_file = argv[2];
    string intersection_ids_file = argv[3];
    string column_ids_csv_file = argv[4];
    size_t batch_size = stoi(argv[5]);
    size_t poly_modulus_degree = stoi(argv[6]);
    int plain_modulus_power = stoi(argv[7]);
    
    vector<string> headers = load_column_ids(column_ids_csv_file);
    
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, plain_modulus_power));
    SEALContext context(parms);
    
    // In a setting where this is done via network communication, 
    // the client would have to send the public key and agree on a context with the server
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    Modulus mod = context.first_context_data()->parms().plain_modulus();
    
    // In a network setting this variable can be send at a later stage after the preprocessing stage
    bytes_to_server += sizeof(public_key);
    Server server(database_csv_file, encryptor, evaluator, batch_encoder, mod, batch_size, poly_modulus_degree, bytes_to_server, headers);
    cout << "Server constructed" << endl;
    
    Client client(query_csv_file, encryptor, decryptor, batch_encoder, mod, batch_size, server, bytes_to_client, headers, intersection_ids_file);
    cout << "Client constructed" << endl;
    
    // Check for valid datasets
    if (!client.init_queries() || !server.init_database()) return 1;
    
    cout << server.get_bytes_to_server() << " bytes sent to server for OPRF" << endl;
    cout << client.get_bytes_to_client() << " bytes sent to client for OPRF" << endl;
    
    chrono::steady_clock::time_point init_end = chrono::steady_clock::now();
    cout << "Time for initialisation = " << chrono::duration_cast<chrono::microseconds>(init_end - begin).count()/60000000.0 << "[min]" << endl;
    
    client.run();
    
    cout << server.get_bytes_to_server() << " bytes sent to server" << endl;
    cout << client.get_bytes_to_client() << " bytes sent to client" << endl;


    chrono::steady_clock::time_point end = chrono::steady_clock::now();
    cout << "Time for online (" << client.get_nr_queries() << " queries) = " << chrono::duration_cast<chrono::microseconds>(end - init_end).count()/60000000.0 << "[min]" << endl;
    cout << "Time for protocol = " << chrono::duration_cast<chrono::microseconds>(end - begin).count()/60000000.0 << "[min]" << endl;

    return 0;
}
