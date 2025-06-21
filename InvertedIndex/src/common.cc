/*
 * This file handles the functions shared between the client and the server
 * For example, encoding strings to integers modulo the plaintext modulus
 */
 
#include "common.h"
#include <sodium.h>

using namespace std;
using namespace seal;
using namespace seal::util;

// Load the database into vectors with the (a,v) pairs
// Only read the columns with the predetermined headers
vector<vector<pair<string, string>>> load_database_csv(const string &filename, const vector<string>& headers) {
    ifstream file(filename);
    vector<vector<pair<string, string>>> data;
    string line;

    if (!file.is_open()) {
        cerr << "Failed to open CSV file." << endl;
        return data;
    }

    vector<string> file_headers;
    if (getline(file, line)) {
        stringstream ss(line);
        string header;
        while (getline(ss, header, ',')) {
            file_headers.push_back(header);
        }
    }

    while (getline(file, line)) {
        stringstream ss(line);
        string cell;
        vector<pair<string, string>> row;
        size_t col = 0, counter = 0;

        while (getline(ss, cell, ',') && col < headers.size()) {
            if (file_headers[counter] != headers[col]) {
                counter++;
                continue;
            }
            if (cell != "") row.emplace_back(headers[col], cell);
            counter++;
            col++;
        }

        if (!row.empty()) {
            data.push_back(row);
        }
    }

    return data;
}

// Encode a symbol so that it may be used as points for the lagrange interpolation
uint64_t encode_symbol(const string& input_str, const Modulus& mod) {
    const unsigned char* input = reinterpret_cast<const unsigned char*>(input_str.data());
    size_t input_len = input_str.size();
    unsigned char hash[crypto_core_ristretto255_HASHBYTES];
    crypto_generichash(hash, sizeof hash, input, input_len, nullptr, 0);
    uint64_t val = 0;
    memcpy(&val, hash, sizeof(uint64_t));
    return val % mod.value();
}

// O(n^3)
// Slightly altered function of Ophir LOJKINE (https://github.com/lovasoa/lagrange-cpp, file: coeffs.cpp)
vector<uint64_t>* lagrange_coeffs(const vector<pair<uint64_t, uint64_t>> points, const Modulus& mod) {
    auto len = points.size();
    auto res = new vector<uint64_t> (len, 0);
    
    for (auto curpoint : points) {
        // As the output of all other points is zero for this point,
        // calculating another polynomial where this point is zero is not needed
        if (curpoint.second == 0) continue;
        vector<uint64_t> tmpcoeffs (len, 0);
        // Start with a constant polynomial
        tmpcoeffs[0] = curpoint.second;
        uint64_t prod = 1;
        for(auto point : points) {
            if (curpoint.first == point.first) continue;
            prod = multiply_uint_mod(prod, sub_uint_mod(curpoint.first, point.first, mod), mod);
            uint64_t precedent = 0;
            for (auto resptr = tmpcoeffs.begin(); resptr < tmpcoeffs.end(); resptr++) {
                // Compute the new coefficient of X^i based on
                // the old coefficients of X^(i-1) and X^i
                uint64_t newres = add_uint_mod(multiply_uint_mod((*resptr),
                                               negate_uint_mod(point.first, mod),
                                               mod), precedent, mod);
                precedent = *resptr;
                *resptr = newres;
            }
        }
        transform(res->begin(), res->end(),
                  tmpcoeffs.begin(),
                  res->begin(),
                  [=] (uint64_t oldcoeff, uint64_t add) {
                    return add_uint_mod(oldcoeff, 
                                        multiply_uint_mod(add, 
                                        exponentiate_uint_mod(prod, mod.value()-2,
                                        mod), mod), mod);
                  } 
                  );
    }
    return res;
}

// For each record, get the polynomial from the points 
vector<vector<uint64_t>> database_poly(vector<vector<pair<uint64_t, uint64_t>>> database, const Modulus& mod) {
    vector<vector<uint64_t>> result;
    for (auto &record : database) {
        result.emplace_back(*lagrange_coeffs(record, mod));
    }
    return result;
}

// Find the polynomial of the highest order in a batch of polynomials
uint64_t find_largest_vector(const vector<vector<uint64_t>>& v) {
    uint64_t max = 0;
    for (size_t i = 0; i < v.size(); i++) {
        if (v[i].size() > max) max = v[i].size();
    }
    return max;
}

// Generate a random scalar
int64_t random_scalar(int64_t modulus) {
    random_device rd;
    mt19937 rng(rd());
    uniform_int_distribution<int64_t> uid(1, modulus - 1);
    return uid(rng);
}

// Generate a vector with random values
vector<uint64_t> random_vector(int64_t size, int mod_value) {
    random_device rd;
    mt19937 rng(rd());
    uniform_int_distribution d(1, mod_value - 1);
    vector<uint64_t> v(size);
    for (int i = 0; i < size; ++i)
        v[i] = d(rng);
    return v;
}

// OPRF functions
// Hash input to a point on the ristretto255 curve
void hash_to_point(unsigned char* point, const unsigned char* input, size_t input_len) {
    unsigned char hash[crypto_core_ristretto255_HASHBYTES];
    crypto_generichash(hash, sizeof hash, input, input_len, nullptr, 0);
    crypto_core_ristretto255_from_hash(point, hash);
}

// Generate a random scalar
void generate_random_scalar(unsigned char* scalar) {
    unsigned char random_bytes[crypto_core_ristretto255_SCALARBYTES];
    randombytes_buf(random_bytes, sizeof random_bytes);
    crypto_core_ristretto255_scalar_reduce(scalar, random_bytes);
}

// Derive uint64_t output from a point mod modulus
uint64_t derive_oprf_output(const unsigned char* point, uint64_t modulus) {
    unsigned char output[crypto_generichash_BYTES];
    crypto_generichash(output, crypto_generichash_BYTES, point, crypto_core_ristretto255_BYTES, nullptr, 0);
    uint64_t val = 0;
    memcpy(&val, output, sizeof(uint64_t));
    return val % modulus;
}
