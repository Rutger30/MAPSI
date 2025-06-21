#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <chrono>
#include <set>

using namespace std;

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

int main(int argc, char *argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <input_csv> <output_csv>" << endl;
        return 1;
    }

    string input_file = argv[1];
    string output_file = argv[2];
    
    ifstream infile(input_file);
    if (!infile.is_open()) {
        cerr << "Failed to open input file: " << input_file << endl;
        return 1;
    }

    string line;
    vector<vector<string>> data;
    set<string> indexes; 

    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    
    // Only take the first column of the input file (the indexes)
    while (getline(infile, line)) {
        string index = split_csv_line(line)[0];
        if (!indexes.count(index)) {
            indexes.insert(index);
        } 
    }
    infile.close();
    cout << "Size of Y: " << indexes.size() << endl;

    ofstream outfile(output_file);
    if (!outfile.is_open()) {
        cerr << "Failed to open output file: " << output_file << endl;
        return 1;
    }

    for (const auto &entry : indexes) {
        outfile << entry << "\n";
    }
    
    chrono::steady_clock::time_point end = chrono::steady_clock::now();
    cout << "Total time receiver transform = " << chrono::duration_cast<chrono::microseconds>(end - begin).count()/1000000.0 
         << "[sec]" << endl;

    outfile.close();
    return 0;
}

