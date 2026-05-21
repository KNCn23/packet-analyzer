CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11 -Iinclude
SRC     = src/parser.c src/cli.c
OBJ     = $(SRC:.c=.o)
TARGET  = pktscan

.PHONY: all clean
all: $(TARGET)
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f $(OBJ) $(TARGET)
