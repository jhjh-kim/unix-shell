CC = gcc
CFLAGS = -Wall

SRC = myshell.c
EXE = myshell

all: $(EXE)

$(EXE) : $(SRC)
	$(CC) $(CFLAGS) -o $@ $^
	@echo "build complete"

clean:
	rm -f $(EXE)
