#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <set>
#include <map>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <algorithm>
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

// Decode base64 encoded data
vector<unsigned char> base64_decode(const string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(encoded.data(), encoded.length());
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

    vector<unsigned char> decoded(encoded.length());
    int decoded_length = BIO_read(bmem, decoded.data(), encoded.length());
    decoded.resize(decoded_length);
    BIO_free_all(bmem);
    return decoded;
}

// Decrypt using AES GCM and the obtained key, iv and tag
bool decrypt_aes_gcm(const vector<unsigned char>& ciphertext, const vector<unsigned char>& iv, 
                     const vector<unsigned char>& tag, const vector<unsigned char>& key, 
                     string& plaintext_out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, plaintext_len = 0;
    vector<unsigned char> plaintext(ciphertext.size());

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) return false;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr)) return false;
    if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) return false;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) return false;
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data())) return false;

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        plaintext_out = string(plaintext.begin(), plaintext.end());
        return true;
    } 
    else return false;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <outputfile_csv> <output_path>\n";
        return 1;
    }
    
    string output_file = argv[1];
    string output_path = argv[2];
    
    // The encrypted file and the intersection file should have the following names
    string encrypted_file = output_path + "EncryptedNetworkData.csv";
    string intersection = output_path + "intersection.csv";

    ifstream infile(intersection);
    if (!infile.is_open()) {
        cerr << "Cannot open input file\n";
        return 1;
    }

    string line;
    
    vector<string> lines;
    map<int, vector<unsigned char>> index_to_key;
    
    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    
    // Split the input file into indexes and keys and map them to each other
    while (getline(infile, line)) {
        auto index = split_csv_line(line)[0];
        auto key = split_csv_line(line)[1];
        index_to_key[stoi(index)] = base64_decode(key);
    }
    cout << index_to_key.size() << " keys" << endl;

   

    ifstream encrfile(encrypted_file);
    if (!encrfile.is_open()) {
        cerr << "Cannot open input file\n";
        return 1;
    }
    
    ofstream outfile(output_file);
    int dec_counter = 0, counter = 1;
    // Loop through the encrypted file, if the index exists in the index to key mapping, decrypt the ciphertext
    while (getline(encrfile, line)) {
        auto row = split_csv_line(line); // 0: ciphertext, 1: tag, 2: iv
        
        // Given that the intersection indexes are correct and the sender sent the rows of the encrypted database in the correct order
        // This will significantly reduce the amount of decryption attempts
        if (index_to_key.count(counter)) {
            string pt;
            if (decrypt_aes_gcm(base64_decode(row[0]), base64_decode(row[2]), base64_decode(row[1]), index_to_key[counter], pt)) {
                outfile << pt << endl;
                dec_counter++;
            }
            else cout << "The key for index " << counter << " seem to be invalid." << endl;
        }
        counter++;
    }
    outfile.close();
    
    chrono::steady_clock::time_point end = chrono::steady_clock::now();
    cout << "Decrypted " << dec_counter << " lines" << endl;
    cout << "Total time receiver decrypt = " << chrono::duration_cast<chrono::microseconds>(end - begin).count()/60000000.0 
         << "[min]" << endl;
    
    return 0;
}

