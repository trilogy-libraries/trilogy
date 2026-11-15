SOURCES = $(shell find src -name '*.c')
TEST_SOURCES = $(shell find test -name '*.c')
OBJS = $(SOURCES:.c=.o)
FUZZ_OBJ = test/fuzz.o

CFLAGS ?= -O1 -ggdb3
CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector
CFLAGS += -Wall -Werror -Wextra -pedantic -Wsign-conversion -Wno-missing-field-initializers -std=gnu99 -iquote inc

OPENSSL = -lssl -lcrypto
EXE =

UNAME_S := $(shell uname -s)
CC_TARGET := $(shell $(CC) -dumpmachine)

ifneq (,$(or $(findstring mingw,$(CC_TARGET)),$(findstring windows,$(CC_TARGET))))
  # Windows with a MinGW-w64 toolchain: native under MSYS2, or cross-compiling
  # with e.g. `CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar make`.
  EXE = .exe
  OPENSSL += -lws2_32 -lcrypt32
  LDFLAGS += -fstack-protector
else ifeq ($(UNAME_S), Darwin)
	CFLAGS += "-I$(shell brew --prefix openssl@3)/include"
	LDFLAGS += "-L$(shell brew --prefix openssl@3)/lib"
else
  CFLAGS += -fPIC
  LDFLAGS += -pie -Wl,-z,relro,-z,now
endif

EXAMPLES = example/trilogy_query$(EXE)
TEST_BIN = test/test$(EXE)

.PHONY: all
all: libtrilogy.a examples

.PHONY: examples
examples: $(EXAMPLES)

example/%$(EXE): example/%.c libtrilogy.a
	$(CC) -o $@ $(CFLAGS) -pedantic $(LDFLAGS) $^ $(OPENSSL)

libtrilogy.a: $(OBJS)
	$(AR) r $@ $^

%.o: %.c inc/trilogy/*.h
	$(CC) -o $@ $(CFLAGS) -pedantic -c $<

debug: CFLAGS += -O0 -ggdb3
debug: all

.PHONY: analyze
analyze:
	$(CC) $(CFLAGS) -pedantic --analyze --analyzer-output text $(SOURCES)

.PHONY: fuzz
fuzz: $(FUZZ_OBJ)

.PHONY: clean
clean:
	rm -f libtrilogy.a $(EXAMPLES) $(OBJS) $(FUZZ_OBJ)
	rm -f $(TEST_BIN) $(TEST_OBJS)

$(TEST_BIN): $(TEST_SOURCES) libtrilogy.a
	$(CC) $(CFLAGS) $(LDFLAGS) -Wno-strict-prototypes -o $(TEST_BIN) $(TEST_SOURCES) -L. -ltrilogy $(OPENSSL)

update_greatest:
	curl -o test/greatest.h https://raw.githubusercontent.com/silentbicycle/greatest/master/greatest.h

.PHONY: test
test: $(TEST_BIN)
	$(TEST_BIN)
