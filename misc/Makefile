CC=gcc
CFLAGS=-Wall -ggdb3 -DBIG_MEM
LCFLAGS=-O2
LEX = flex
YACC=bison
LEXLIB = -lfl
YAS=./yas

all: yis yas hcl2c bus lock.o

# These are implicit rules for making .yo files from .ys files.
# E.g., make sum.yo
.SUFFIXES: .ys .yo
.ys.yo:
	$(YAS) $*.ys

# These are the explicit rules for making yis yas and hcl2c and hcl2v
yas-grammar.o: yas-grammar.c
	$(CC) $(LCFLAGS) -c yas-grammar.c

yas-grammar.c: yas-grammar.lex
	$(LEX) yas-grammar.lex
	mv lex.yy.c yas-grammar.c

lock.o: lock.c lock.h
	$(CC) $(CFLAGS) -c lock.c

isa.o: isa.c isa.h lock.o
	$(CC) $(CFLAGS) -c isa.c

yas.o: yas.c yas.h isa.h lock.o
	$(CC) $(CFLAGS) -c yas.c

yas: yas.o yas-grammar.o isa.o lock.o
	$(CC) $(CFLAGS) yas-grammar.o lock.o yas.o isa.o ${LEXLIB} -o yas

yis.o: yis.c isa.h
	$(CC) $(CFLAGS) -c yis.c

yis: yis.o isa.o lock.o
	$(CC) $(CFLAGS) yis.o lock.o isa.o -o yis

hcl2c: hcl.tab.c lex.yy.c node.c outgen.c
	$(CC) $(LCFLAGS) node.c lex.yy.c hcl.tab.c outgen.c -o hcl2c

hcl2v: hcl.tab.c lex.yy.c node.c outgen.c
	$(CC) $(LCFLAGS) -DVLOG node.c lex.yy.c hcl.tab.c outgen.c -o hcl2v

hcl2u: hcl.tab.c lex.yy.c node.c outgen.c
	$(CC) $(LCFLAGS) -DUCLID node.c lex.yy.c hcl.tab.c outgen.c -o hcl2u

lex.yy.c: hcl.lex
	$(LEX) hcl.lex

hcl.tab.c: hcl.y
	$(YACC) -d hcl.y

lock.o: lock.c
	$(CC) $(CFLAGS) -c lock.c

bus: bus.c
	$(CC) $(CFLAGS) bus.c -o bus

clean:
	rm -f *.o *.yo *.exe yis yas hcl2c mux4 *~ core.*
	rm -f hcl.tab.c hcl.tab.h lex.yy.c
