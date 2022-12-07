CXX=g++
CXXFLAGS=--std=c++17  -march=native -O3 -g -Wno-ignored-attributes 
LIBS= -lbsd -lssl -lcrypto

default: simulator verifier gen_lowmc_consts

simulator: simulator.cpp utils.h dpf.h prg.h lowmc.h proof.h  block.h simulator.h randomness.h verifier.h verifierP2.h transcripts.h
	$(CXX) $(CXXFLAGS) -o simulator simulator.cpp -DLOWMC $(LIBS)

genconsts: gen_lowmc_consts.cpp
	$(CXX) $(CXXFLAGS) -o gen_lowmc_const gen_lowmc_consts.cpp -DLOWMC $(LIBS)

verifier: verifier.cpp dpf.h prg.h lowmc.h block.h simulator.h randomness.h verifier.h verifier2.h transcripts.h
	$(CXX) $(CXXFLAGS) -o verifier verifier.cpp -DLOWMC $(LIBS)

unrank: unrank.cpp
	$(CXX) $(CXXFLAGS) -o unrank unrank.cpp -DLOWMC $(LIBS)

# dpflowmc: dpf.cpp dpf.h prg.h LowMC.h LowMC.cpp block.h
# 	$(CXX) $(CXXFLAGS) -o dpflowmc lowmc.cpp dpf.cpp -DLOWMC $(LIBS)

# dpfaes: dpf.cpp dpf.h prg.h aes.h block.h 
# 	$(CXX) $(CXXFLAGS) -o dpfaes dpf.cpp -DAES $(LIBS)

# zkplowmc: mpcZkp.cpp dpf.h prg.h LowMC.h  aes.h block.h 
# 	$(CXX) $(CXXFLAGS) -DLOWMC dpf.h LowMC.h prg.h aes.h block.h LowMC.cpp -o mpczkplowmc mpcZkp.cpp $(LIBS)

clean:
	rm -f  simulator verifier genconsts #dpflowmc dpfaes

