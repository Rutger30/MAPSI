#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <chrono>

using namespace std;

// Concatenate non-empty cells per row with row id (to make sure e.g. sIP and dIP don't match)
vector<string> ReceiverTransform(const vector<vector<string>> &rows) {
    vector<string> transformed;
    for (const auto &row : rows) {
        string temp;
        for (int i = 0; i < row.size(); i++) {
            if (!row[i].empty()) {
                temp += to_string(i) + row[i];
            }
        }
        transformed.push_back(temp);
    }
    cout << "Size of Y: " << transformed.size() << endl;
    return transformed;
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

int main(int argc, char *argv[]) {
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <input_csv> <output_csv> <column_ids_csv>" << endl;
        return 1;
    }

    string input_file = argv[1];
    string output_file = argv[2];
    string column_ids_csv = argv[3];
    
    vector<string> headers = load_column_ids(column_ids_csv);
    

    ifstream infile(input_file);
    if (!infile.is_open()) {
        cerr << "Failed to open input file: " << input_file << endl;
        return 1;
    }

    string line;
    vector<vector<string>> data;

    vector<string> file_headers;
    // Get the headers of the input set Y
    if (getline(infile, line)) {
        stringstream ss(line);
        string header;
        while (getline(ss, header, ',')) {
            file_headers.push_back(header);
        }
    }

    chrono::steady_clock::time_point begin = chrono::steady_clock::now();
    
    while (getline(infile, line)) {
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
    infile.close();

    vector<string> transformed_data = ReceiverTransform(data);

    ofstream outfile(output_file);
    if (!outfile.is_open()) {
        cerr << "Failed to open output file: " << output_file << endl;
        return 1;
    }

    for (const auto &entry : transformed_data) {
        outfile << entry << "\n";
    }
    
    chrono::steady_clock::time_point end = chrono::steady_clock::now();
    cout << "Total time receiver transform = " << chrono::duration_cast<chrono::microseconds>(end - begin).count()/1000000.0 
         << "[sec]" << endl;

    outfile.close();
    return 0;
}

