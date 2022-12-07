CXX=g++
CXXFLAGS=--std=c++17 -march=native -O3 -g -Wno-ignored-attributes  -fopenmp -DBOOST_ERROR_CODE_HEADER_ONLY #-DDEBUG #-DVERBOSE
LIBS=-lbsd -lboost_system -lboost_thread -pthread

default: p0 p1 p2 p3 gen_queries

dotprod: dotprod2.cpp prg.h common.h 
	$(CXX) $(CXXFLAGS) -o dotprod  dotprod2.cpp $(LIBS) -I.

p0: pB.cpp common.h 
	$(CXX) $(CXXFLAGS) -o p0 pB.cpp $(LIBS) -DPARTY=0 -I.

p1: pB.cpp common.h
	$(CXX) $(CXXFLAGS) -o p1 pB.cpp $(LIBS) -DPARTY=1 -I.

p2: p2.cpp network.h aes.h common.h 
	$(CXX) $(CXXFLAGS) -o p2 p2.cpp $(LIBS) -I.

p3: p3.cpp network.h aes.h common.h 
	$(CXX) $(CXXFLAGS) -o p3 p3.cpp $(LIBS) -I.

gen_queries: gen_queries.cpp rand_queries.cpp common.h
	touch queries
	touch queries.0
	touch queries.1
	$(CXX) $(CXXFLAGS) -o gen_queries gen_queries.cpp $(LIBS)
	$(CXX) $(CXXFLAGS) -o rand_queries rand_queries.cpp $(LIBS)

mwe: mwe.cpp  aes.h  common.h
	$(CXX) $(CXXFLAGS) -o mwe mwe.cpp -DAES $(LIBS) -I.

clean:
	rm -f p0 p1 p2 p3 gen_queries

kill:
	pkill p2 & pkill p1 & pkill p0 & pkill p3

