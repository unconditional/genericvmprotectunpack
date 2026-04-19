# genericvmprotectunpack
a generic ( global ) vmprotect unpacker, the devirtualization may not work we need add more opcodes. but the dumper work well

### Build Steps

```bash
# Clone the repo
git clone https://github.com/devirtz/genericvmprotectunpack.git
cd genericvmprotectunpack

# Configure with CMake
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release



#### Creds
forked from sudha2323/vmprotectunpacker