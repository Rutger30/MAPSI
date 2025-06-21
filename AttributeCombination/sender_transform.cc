#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <set>
#include <map>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <algorithm>
#include <filesystem>
#include <chrono>

using namespace std;

const int AES_KEY_SIZE = 32; // AES-256
const int GCM_IV_SIZE = 12;
const int GCM_TAG_SIZE = 16;

// Split a line from the input file into a vector 
vector<string> split_csv_line(const string& line) {
    vector<string> tokens;
    string token;
    istringstream stream(line);
    while (getline(stream, token, ',')) {
        tokens.push_back(token);
    }
    return tokens;
}

// Generate a random key for AES-256
vector<unsigned char> generate_aes_key() {
    vector<unsigned char> key(AES_KEY_SIZE);
    RAND_bytes(key.data(), AES_KEY_SIZE);
    return key;
}

// Encode a byte string into base64
string base64_encode(const unsigned char* buffer, size_t length) {
    BIO* bmem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bmem);
    BIO_write(b64, buffer, length);
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    string encoded(bptr->data, bptr->length);
    BIO_free_all(b64);
    
    return encoded;
}

// Encrypts the lines using AES-GCM
bool encrypt_aes_gcm(const string& plaintext, const vector<unsigned char>& key,
                     vector<unsigned char>& ciphertext, vector<unsigned char>& iv, vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    iv.resize(GCM_IV_SIZE);
    RAND_bytes(iv.data(), GCM_IV_SIZE);
    ciphertext.resize(plaintext.size());
    tag.resize(GCM_TAG_SIZE);
    
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
    ciphertext_len = len;
    
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Generate all non-empty combinations of a row
set<string> get_combinations(const vector<string>& row) {
    set<string> combis;
    int n = row.size();
    // Loop through all possible combinations
    for (int r = 1; r <= n; r++) {
        vector<bool> mask(n);
        fill(mask.end() - r, mask.end(), true);
        do {
            string combi;
            bool skip = false;
            for (int i = 0; i < n; i++) {
                if (mask[i]) {
                    if (row[i].empty()) {
                        skip = true;
                        break;
                    }
                    // Add the column number to differentiate between columns
                    // Note that this works only for max 10 columns (0-9)
                    // A more general approach would take log2(|columns|) bits
                    // and assign a unique bitstring per column to prepend
                    combi += to_string(i) + row[i];
                }
            }
            if (!skip) {
                combis.insert(combi);
            }
        } while (next_permutation(mask.begin(), mask.end()));
    }
    return combis;
}

// Read the headers of the columns used in the intersection
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

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <input_csv> <output_path> <column_ids_csv>" << endl;
        return 1;
    }

    string inputFile = argv[1];
    string baseFile = argv[2];
    string column_ids_csv = argv[3];
    
    vector<string> headers = load_column_ids(column_ids_csv);

    ifstream infile(inputFile);
    if (!infile.is_open()) {
        cerr << "Cannot open input file\n";
        return 1;
    }

    string line;
    vector<string> file_headers;
    // Get the headers of the input set X
    if (getline(infile, line)) {
        stringstream ss(line);
        string header;
        while (getline(ss, header, ',')) {
            file_headers.push_back(header);
        }
    }
    vector<string> lines;
    map<string, vector<int>> combi_to_indexes;
    
    // Start timer
    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    vector<vector<string>> data;
    
    while (getline(infile, line)) {
        lines.push_back(line);
        stringstream ss(line);
        string cell;
        vector<string> row;
        size_t col = 0, counter = 0;

        // Per row, get only the correct columns (as specified by the columns file)
        while (getline(ss, cell, ',') && col < headers.size()) {
            if (file_headers[counter] != headers[col]) {
                counter++;
                continue;
            }
            row.push_back(cell);
            counter++;
            col++;
        }

        data.push_back(row);
    }
    
    int index = 0;
    // Get all combinations
    for (const auto& row : data) {
        auto combis = get_combinations(row);
        // Keep track of a list of records associated with a combination
        for (const auto& c : combis) {
            combi_to_indexes[c].push_back(index);
        }
        index++;
    }
    
    infile.close();

    chrono::steady_clock::time_point combi_time = chrono::steady_clock::now();
    cout << "Time for " << combi_to_indexes.size() << " combinations = " 
         << chrono::duration_cast<chrono::microseconds>(combi_time - begin).count()/60000000.0 
         << "[min]" << endl;    
    
    map<vector<int>, vector<string>> indexes_to_combis;
    map<vector<int>, vector<unsigned char>> indexes_to_keys;
    set<vector<int>> seen; // Keep track of which combination of indexes we have seen
    
    // Loop through all combinations and their associated indexes
    // Generate a key for each unique combination of indexes
    for (const auto& [combi, indexes] : combi_to_indexes) {
        if (!seen.count(indexes)) {
            auto key = generate_aes_key();
            indexes_to_keys[indexes] = key;
            seen.insert(indexes);
        } 
        indexes_to_combis[indexes].push_back(combi);
    }
    
    chrono::steady_clock::time_point uniques_time = chrono::steady_clock::now();
    cout << "Time for " << seen.size() << " unique keys = " 
         << chrono::duration_cast<chrono::microseconds>(uniques_time - combi_time).count()/60000000.0 
         << "[min]" << endl;
    
    vector<tuple<string, string, string>> encrypted_lines;
    // For each combination of indexes, encrypt these records with the associated keys
    for (const auto& [indexes, key] : indexes_to_keys) {
        for (int i : indexes) {
            vector<unsigned char> ct, iv, tag;
            encrypt_aes_gcm(lines[i], key, ct, iv, tag);
            encrypted_lines.push_back({
                base64_encode(ct.data(), ct.size()),
                base64_encode(tag.data(), tag.size()),
                base64_encode(iv.data(), iv.size())
            });
        }
    }
    
    
    chrono::steady_clock::time_point encrypt_time = chrono::steady_clock::now();
    cout << "Time for " << encrypted_lines.size() << " encryptions = " 
         << chrono::duration_cast<chrono::microseconds>(encrypt_time - uniques_time).count()/60000000.0 
         << "[min]" << endl;

    ofstream ef(baseFile + "EncryptedNetworkData.csv");
    for (const auto& [ct, tag, iv] : encrypted_lines) {
        ef << ct << "," << tag << "," << iv << "\n";
    }
    ef.close();

    filesystem::path filePath = baseFile + "EncryptedNetworkData.csv";
    cout << "File size is: " << filesystem::file_size(filePath) << " bytes" << endl; // File size and thus communication in bytes

    ofstream tf(baseFile + "tempNetworkData.csv");
    for (const auto& [combi, indexes] : combi_to_indexes) {
        tf << combi << "," << base64_encode(indexes_to_keys[indexes].data(), indexes_to_keys[indexes].size()) << "\n";
    }
    tf.close();

    cout << "Encrypted " << encrypted_lines.size() << " lines using "
         << indexes_to_keys.size() << " unique sets of indexes.\n";
         
    chrono::steady_clock::time_point end = chrono::steady_clock::now();
    cout << "Time for writing files = " << chrono::duration_cast<chrono::microseconds>(end - uniques_time).count()/60000000.0 
         << "[min]" << endl;
    
    cout << "Total time sender transform = " << chrono::duration_cast<chrono::microseconds>(end - begin).count()/60000000.0 
         << "[min]" << endl;

    return 0;
}

