CPP      = g++
OBJ      = main.o src/key.o src/pubkey.o src/uint256.o src/utilstrencodings.o secp256k1/src/secp256k1.o \
inc/crypto/ripemd160.o inc/crypto/sha256.o inc/crypto/sha512.o inc/crypto/hmac_sha512.o src/hash.o inc/script/standard.o \
inc/script/script.o inc/script/script_error.o src/keystore.o inc/primitives/transaction.o \
inc/script/interpreter.o inc/crypto/sha1.o inc/script/sign.o inc/univalue/lib/univalue.o src/bech32.o \
inc/univalue/lib/univalue_get.o inc/univalue/lib/univalue_read.o inc/univalue/lib/univalue_write.o inc/support/cleanse.o \
inc/primitives/block.o src/netaddress.o inc/consensus/merkle.o src/chainparams.o src/chainparamsbase.o src/base58.o
LIBS     = -L"/usr/lib" -L"/usr/local/lib"
BIN      = genAddress

# CXXFLAGS变量名固定的？？且自动引用？？
CXXFLAGS = -I"./inc" -I"./secp256k1/include" -I"./inc/univalue/include" -std=gnu++0x


all: $(BIN)
	@echo "Build Successfully !!!"

$(BIN): $(OBJ)
	$(CPP) $(OBJ) -o $(BIN) $(LIBS)



%.o: %.cpp
	$(CPP) -c $< -o $@ $(CXXFLAGS)
	
%.o: %.c
	$(CPP) -c $< -o $@ $(CXXFLAGS)





clean:
	rm -f $(OBJ) $(BIN)