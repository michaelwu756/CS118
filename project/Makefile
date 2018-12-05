CXX=g++
CXXOPTIMIZE= -O2
CXXFLAGS= -g -Wall -pthread -std=c++11 -I. -Ibuild/ $(CXXOPTIMIZE)
LDFLAGS=-lIce -lIceUtil -lboost_system -pthread
SLICE_INCLUDES=-I/usr/share/Ice/slice

USERID=404751542

CLASSES=build/pox.o arp-cache.o routing-table.o simple-router.o core/utils.o core/interface.o core/dumper.o

all: router

build/pox.cpp: core/pox.ice
	mkdir -p build
	slice2cpp $(SLICE_INCLUDES) --output-dir=build --header-ext=hpp $<

router: $(CLASSES) core/main.o
	$(CXX) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf *.o *~ *.gch *.swp *.dSYM router *.tar.gz pox.hpp pox.cpp build/ *.pyc core/*.o

dist: tarball
tarball: clean
	tar -cvzf /tmp/$(USERID).tar.gz arp-cache.cpp arp-cache.hpp client COPYING.md core/dumper.cpp core/dumper.hpp core/interface.cpp core/interface.hpp core/main.cpp core/pox.ice core/protocol.hpp core/utils.cpp core/utils.hpp IP_CONFIG Makefile out.file pox.service README.md router.config routing-table.cpp routing-table.hpp RTABLE run.py server show-arp.py simple-router.cpp simple-router.hpp temp test.file Vagrantfile && mv /tmp/$(USERID).tar.gz .
