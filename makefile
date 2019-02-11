CC=g++

ODIR=obj

SRC=src

_OBJ = sandbox.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: $(SRC)/%.cpp 
	mkdir -p -- $(ODIR)
	$(CC) -c -o $@ $< 

fend: $(OBJ)
	$(CC) -o $@ $^ 

run: sandbox
	./sandbox

.PHONY: clean

clean:
	rm -rf $(ODIR) sandbox 