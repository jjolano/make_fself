TARGET = make_fself
CC = gcc
CXX = g++
LD = $(CXX)
CFLAGS = -Wno-deprecated-declarations
CXXFLAGS = $(CFLAGS)
LDFLAGS = -lcrypto
OBJS = main.o

.PHONY: test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) $^ $(LDFLAGS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJS) $(TARGET)
