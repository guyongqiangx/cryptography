.PHONY: all clean sha256 test

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

SRCS    = utils.c sha256.c sha256test.c
TARGET  = sha256

OBJS 	= $(SRCS:.c=.o)

all: sha256 test

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LIBS) $(INCLUDE)
#	$(STRIP) --strip-all $(TARGET)

test: $(TARGET)
	@echo
	@echo "Run Test..."
	./$(TARGET) -a sha224 -x
	./$(TARGET) -a sha256 -x

clean:
	$(RM) $(RMFLAGS) $(TARGET) $(OBJS)
