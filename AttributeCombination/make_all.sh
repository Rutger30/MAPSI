g++ -std=c++17 -o sender_transform sender_transform.cc -lssl -lcrypto
g++ receiver_transform.cc -o receiver_transform
g++ -std=c++17 -o receiver_decrypt receiver_decrypt.cc -lssl -lcrypto
