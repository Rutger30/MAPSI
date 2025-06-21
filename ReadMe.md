# Multi-Attribute Private Set Intersection
In this project we implement a proof of concept of our protocols proposed in the thesis:

[**Private Matching of IoC and Network Data**](http://repository.tudelft.nl/)

## Installing the dependencies
This project requires the following packages and projects to run:
```
sudo apt-get install pkg-config libssl-dev build-essential curl git libsodium-dev
```
Install [VCPKG](https://github.com/microsoft/vcpkg) in the root of this project and run the following:
```
./vcpkg install seal[no-throw-tran] kuku log4cplus cppzmq flatbuffers jsoncpp tclap
```
Install [APSI](https://github.com/microsoft/APSI) in the root of this project and build it as follows:
```
mkdir APSI/build && cd APSI/build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../vcpkg/scripts/buildsystems/vcpkg.cmake -DAPSI_BUILD_CLI=ON
make
```

## Building and running the project
### Inverted Index PSI
To compile and run the code, run the following commands:
```
cd /InvertedIndex/
./APSIPeripheral/make_all.sh
cmake -S . -B build

./build/InvertedIndex $NetworkData.csv $IoC.csv $IIintersection.csv $Attributes.csv $No.Clusters $No.SlotInCiphertext(Batches) $PolynomialModulusDegree > $Logfile1.txt
    
./run_sender.sh $DataPath $NetworkData.csv $APSILogfileSender.txt > $Logfile2.txt &
        
./run_receiver.sh $DataPath $IIintersection.csv intersection.csv $FinalIntersection.csv $APSILogfileReceiver.txt 127.0.0.1 > $Logfile3.txt
```
Replace the bash variables with the desired input or output files.

### Attribute Combination PSI
To compile the code, run the following commands:
```
cd /AttributeCombination/
./make_all.sh

./sender.sh $DataPath $NetworkData.csv $/Path/Attributes.csv $APSILogfileSender.txt > $Logfile1.txt &

./receiver.sh $DataPath $IoC.csv intersection.csv $FinalIntersection.csv $APSILogfileReceiver.txt 127.0.0.1 $/Path/Attributes.csv > $Logfile2.txt
```
Replace the bash variables with the desired input or output files.
