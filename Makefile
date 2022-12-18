CC = g++
CFLAGS = -Wall -Wextra -ggdb
LIBS = -lcrypto
SRC = base64.cpp Crypto.cpp

EXAMPLE_TARGET = Digital_Envelope

FILE_EXAMPLE_TARGET = Digital_Envelope_file

.PHONY: all text file test clean

all: text file


text:
	$(CC) $(CFLAGS) -o $(EXAMPLE_TARGET) $(SRC) Digital_Envelope.cpp $(LIBS)


# file:
# 	 $(CC) $(CFLAGS) -o $(FILE_EXAMPLE_TARGET) $(SRC) Digital_Envelope_file.cpp $(LIBS)

test:
	./$(EXAMPLE_TARGET)

clean:
	rm $(EXAMPLE_TARGET) $(FILE_EXAMPLE_TARGET)

