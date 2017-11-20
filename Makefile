#
# Makefile : ISA 2017, Martin Pumr
# src/
#

CXX         = g++
CXXFLAGS    = -std=gnu++11 -Wall -Wextra -pedantic -Werror #-O2 #-DNDEBUG

.PHONY : all
.PHONY : clean

all : isamon

isamon : isamon.cpp global.o target.o scanner.o packet.o sniffer.o lock.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -pthread

global.o : global.cpp
	$(CXX) $(CXXFLAGS) -c $^

target.o: target.cpp
	$(CXX) $(CXXFLAGS) -c $^

scanner.o: scanner.cpp
	$(CXX) $(CXXFLAGS) -c $^

packet.o: packet.cpp
	$(CXX) $(CXXFLAGS) -c $^

sniffer.o: sniffer.cpp
	$(CXX) $(CXXFLAGS) -c $^

lock.o: lock.cpp
	$(CXX) $(CXXFLAGS) -c $^


clean :
	rm -f *.o
	rm -f isamon
