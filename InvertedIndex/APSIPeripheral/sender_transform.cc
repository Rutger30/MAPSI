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

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <input_csv> <output_path>" << endl;
        return 1;
    }

    string inputFile = argv[1];
    string baseFile = argv[2];

    ifstream infile(inputFile);
    if (!infile.is_open()) {
        cerr << "Cannot open input file\n";
        return 1;
    }

    string line;
    if (!getline(infile, line)) {
        cerr << "Empty file" << endl;
        return 1;
    }
    
    vector<string> lines;
    
    // Start timer
    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    
    while (getline(infile, line)) {
        lines.push_back(line);
    }
    infile.close();

    map<int, vector<unsigned char>> indexes_to_keys;
    // Generate a key for each index
    for (size_t i = 0; i < lines.size(); i++) {
        auto key = generate_aes_key();
        indexes_to_keys[i+1] = key;
    }
    
    chrono::steady_clock::time_point uniques_time = chrono::steady_clock::now();
    cout << "Time for " << lines.size() << " unique keys = " 
         << chrono::duration_cast<chrono::microseconds>(uniques_time - begin).count()/60000000.0 
         << "[min]" << endl;
    
    vector<tuple<string, string, string>> encrypted_lines;
    // Encrypt all lines using the associated key
    for (const auto& [index, key] : indexes_to_keys) {
        vector<unsigned char> ct, iv, tag;
        encrypt_aes_gcm(lines[index-1], key, ct, iv, tag);
        encrypted_lines.push_back({
            base64_encode(ct.data(), ct.size()),
            base64_encode(tag.data(), tag.size()),
            base64_encode(iv.data(), iv.size())
        });
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
    for (const auto& [index, key] : indexes_to_keys) {
        tf << index << "," << base64_encode(key.data(), key.size()) << "\n";
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

