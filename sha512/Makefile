.PHONY: all clean sha512 test

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

SRCS    = utils.c sha512.c sha512test.c
TARGET  = sha512

OBJS 	= $(SRCS:.c=.o)

all: sha512 test

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS) $(INCLUDE)
#	$(STRIP) --strip-all $(TARGET)

test: $(TARGET)
	@echo
	@echo "Run Test..."
	./$(TARGET) -a sha384 -x
	./$(TARGET) -a sha512 -x
	./$(TARGET) -a sha512-224 -x
	./$(TARGET) -a sha512-256 -x
	./$(TARGET) -a sha512t -t 224 -x
	./$(TARGET) -a sha384 -f $(TARGET)
	./$(TARGET) -a sha512 -f $(TARGET)
	./$(TARGET) -a sha512-224 -f $(TARGET)
	./$(TARGET) -a sha512-256 -f $(TARGET)
	./$(TARGET) -a sha512t -t 224 -f $(TARGET)

clean:
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS)
