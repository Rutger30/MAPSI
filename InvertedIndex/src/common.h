#pragma once
#include "seal/seal.h"
#include "seal/util/uintarithsmallmod.h"
#include <vector>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <string>
#include <random>
#include <sstream>
#include <chrono>
#include <iomanip>


std::vector<std::vector<std::pair<std::string, std::string>>> load_database_csv(const std::string &filename, const std::vector<std::string>& headers);

uint64_t encode_symbol(const std::string& input_str, const seal::Modulus& mod);

std::vector<uint64_t>* lagrange_coeffs(const std::vector<std::pair<uint64_t, uint64_t>> points, const seal::Modulus& mod);

std::vector<std::vector<uint64_t>> database_poly(std::vector<std::vector<std::pair<uint64_t, uint64_t>>> database, const seal::Modulus& mod);

uint64_t find_largest_vector(const std::vector<std::vector<uint64_t>>& v);

int64_t random_scalar(int64_t modulus);

std::vector<uint64_t> random_vector(int64_t size, int mod_value);

void hash_to_point(unsigned char* point, const unsigned char* input, size_t input_len);

void generate_random_scalar(unsigned char* scalar);

uint64_t derive_oprf_output(const unsigned char* point, uint64_t modulus);
