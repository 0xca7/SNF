# SNF
### Simple Network Fuzzer

... is a very simple TCP/IP options fuzzer. The idea for this
project came from `fuzzball2` which is, to my best knowledge, 
not actively developed anymore. 

To fuzz with SNF, do the following:

```
./snf -t [TARGET IP] -p [TARGET PORT] -i [INTERFACE NAME] -m [MODE]    
# mode is either 0 for IP options or 1 for TCP options fuzzing
```


## Dependencies

all you need is `cmake` and `ninja-tools`.

```
sudo apt-get install cmake ninja-tools
```

... and to recursively clone this repo to get unity
if you intend to do unit testing.

## Building

first step:
```
cd src
cmake -GNinja CMakeLists.txt
chmod +x build
```

building the release:
```
cd src
./build release
```

building the tests:
```
cd src
./build test
```

clean the project:
```
cd src
./build clean
```

## Structure

The `src` folder contains the source code and the means to build.
It is structured as follows:

    - `modules` contains the individual code modules
    - `tests` contains the unit tests for the code modules
    - `main` contains the main.c file for the release build
    - `external` contains any external code
    - `global` contains global headers, configs, etc.

## Documentation

doc contains `splint` outputs, source code documentation (doxy files)
etc.

### 0xca7
