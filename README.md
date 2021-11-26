# SNF
SNF - Simple Network Fuzzer

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

## Documentation

doc contains `splint` outputs, source code documentation (doxy files)
etc.

### 0xca7
