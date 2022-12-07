CXX=g++
CXXFLAGS=--std=c++17 -march=native -O3 -g -Wno-ignored-attributes
LIBS=-lbsd 

default: simulator #verifier

simulator: simulator.cpp dpf.h prg.h lowmc.h lowmc.cpp block.h simulator.h randomness.h verifier.h verifier2.h transcripts.h
	$(CXX) $(CXXFLAGS) -o simulator lowmc.cpp simulator.cpp -DLOWMC $(LIBS)

verifier: verifier.cpp dpf.h prg.h lowmc.h lowmc.cpp block.h simulator.h randomness.h verifier.h verifier2.h transcripts.h
	$(CXX) $(CXXFLAGS) -o verifier lowmc.cpp verifier.cpp -DLOWMC $(LIBS)
# dpf: new_dpf.cpp new_dpf.h prg.h LowMC.h LowMC.cpp block.h
# 	$(CXX) $(CXXFLAGS) -o dpf lowmc.cpp new_dpf.cpp -DLOWMC $(LIBS)

# dpflowmc: dpf.cpp dpf.h prg.h LowMC.h LowMC.cpp block.h
# 	$(CXX) $(CXXFLAGS) -o dpflowmc lowmc.cpp dpf.cpp -DLOWMC $(LIBS)

# dpfaes: dpf.cpp dpf.h prg.h aes.h block.h 
# 	$(CXX) $(CXXFLAGS) -o dpfaes dpf.cpp -DAES $(LIBS)

# zkplowmc: mpcZkp.cpp dpf.h prg.h LowMC.h  aes.h block.h 
# 	$(CXX) $(CXXFLAGS) -DLOWMC dpf.h LowMC.h prg.h aes.h block.h LowMC.cpp -o mpczkplowmc mpcZkp.cpp $(LIBS)

clean:
	rm -f  simulator verifier #dpflowmc dpfaes

