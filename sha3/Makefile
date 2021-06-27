.PHONY: all clean sha3 test

CROSS_COMPILE=

CC      = $(CROSS_COMPILE)gcc
STRIP   = $(CROSS_COMPILE)strip
AR      = $(CROSS_COMPILE)ar
ARFLAGS = crs

RM      = rm
RMFLAGS = -rf

LIBS    =
INCLUDE =
CFLAGS  = -Wall -g -O2

SRCS    = utils.c sha3.c sha3test.c
TARGET  = sha3

OBJS 	= $(SRCS:.c=.o)

all: sha3 test

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS) $(INCLUDE)
#	$(STRIP) --strip-all $(TARGET)

test: $(TARGET)
	@echo
	@echo "Run Test..."
	./$(TARGET) -a sha3-224 -x
	./$(TARGET) -a sha3-256 -x
	./$(TARGET) -a sha3-384 -x
	./$(TARGET) -a sha3-512 -x
	./$(TARGET) -a shake128 -d 128 -x
	./$(TARGET) -a shake128 -x
	./$(TARGET) -a shake256 -d 256 -x
	./$(TARGET) -a shake256 -x
	./$(TARGET) -a sha3-224 -f $(TARGET)
	./$(TARGET) -a sha3-256 -f $(TARGET)
	./$(TARGET) -a sha3-384 -f $(TARGET)
	./$(TARGET) -a sha3-512 -f $(TARGET)
	./$(TARGET) -a shake128 -d 128 -f $(TARGET)
	./$(TARGET) -a shake128 -f $(TARGET)
	./$(TARGET) -a shake256 -d 256 -f $(TARGET)
	./$(TARGET) -a shake256 -f $(TARGET)

clean:
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS)
