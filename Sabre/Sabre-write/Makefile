## Sabre, an anonymous bulletin board with speedier ripostes
#  Copyright (C) 2020  Sabre authors
#
#  @file    Makefile
#  @brief   Makefile for compiling Sabre
#
#  @author  Ryan Henry        <ryan.henry@ucalgary.ca>
#  @author  Adithya Vadapalli <avadapal@iu.edu>
#  @author  Kyle Storrier     <kyle.storrier@ucalgary.ca>
#
#  @license GNU Public License (version 2); see LICENSE for full license text
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

BLOCK_LEN = 128
ROUNDS    = 19
SBOXES    = 32
NDPFS     = 256

CXX = g++
CXXFLAGS = -g -march=native -std=c++17 -Wall -pedantic -fopenmp -O3 -Wno-ignored-attributes -pthread
LIBS = -lbsd
FLAGS = -DDPFPP_DO_LOWMC -DBLOCK_LEN=$(BLOCK_LEN) -DROUNDS=$(ROUNDS) -DSBOXES=$(SBOXES) -DNDPFS=$(NDPFS)

OPENSSL_INCLUDE ?= -I/usr/include/openssl
CXXFLAGS += $(OPENSSL_INCLUDE)
OPENSSL_LIBS ?= -lcrypto
LIBS += $(OPENSSL_LIBS)

BINDIR = bin

all: directories $(BINDIR)/sabre

$(BINDIR)/sabre: $(BINDIR) $(BINDIR)/gen_constants sabre.cpp lowmc/lowmc.h dpf++/dpf.h
	$(CXX) $(CXXFLAGS) -o $(BINDIR)/sabre sabre.cpp $(LIBS) $(FLAGS)

$(BINDIR)/gen_constants: $(BINDIR) lowmc/gen_constants.cpp
	$(CXX) $(CXXFLAGS) -o $(BINDIR)/gen_constants lowmc/gen_constants.cpp $(LIBS) $(FLAGS)
	@test -f lowmc/constants_b$(BLOCK_LEN)_r$(ROUNDS)_s$(SBOXES).h || ./$(BINDIR)/gen_constants > lowmc/constants_b$(BLOCK_LEN)_r$(ROUNDS)_s$(SBOXES).h

$(BINDIR)/recipegen: $(BINDIR) lowmc/recipegen.cpp
	$(CXX) $(CXXFLAGS) -o $(BINDIR)/recipegen lowmc/recipegen.cpp $(LIBS) $(FLAGS)
	@test -f lowmc/recipe_b$(BLOCK_LEN)_r$(ROUNDS)_s$(SBOXES).h || ./$(BINDIR)/recipegen > lowmc/recipe_b$(BLOCK_LEN)_r$(ROUNDS)_s$(SBOXES).h

docs:
	doxygen Doxyfile

.PHONY: directories

directories: $(BINDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -f $(BINDIR)/sabre $(BINDIR)/gen_constants

veryclean: clean
	rm -rf lowmc/constants_b*_r*_s*.h
	rm -rf $(BINDIR) doc

