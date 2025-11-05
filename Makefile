SOURCES = $(shell find src -name '*.c')
TEST_SOURCES = $(shell find test -name '*.c')
OBJS = $(SOURCES:.c=.o)
FUZZ_OBJ = test/fuzz.o

CFLAGS ?= -O1 -ggdb3
CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector
CFLAGS += -Wall -Werror -Wextra -pedantic -Wsign-conversion -Wno-missing-field-initializers -std=gnu99 -iquote inc

OPENSSL = -lcrypto -lssl
EXAMPLES = example/trilogy_query example/trilogy_binlog

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Darwin)
	CFLAGS += "-I$(shell brew --prefix openssl@1.1)/include"
	LDFLAGS += "-L$(shell brew --prefix openssl@1.1)/lib"
else
  CFLAGS += -fPIC
  LDFLAGS += -pie -Wl,-z,relro,-z,now
endif

.PHONY: all
all: libtrilogy.a examples

.PHONY: examples
examples: $(EXAMPLES)

example/%: example/%.c libtrilogy.a
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
	rm -f test/test $(TEST_OBJS)

test/test: $(TEST_SOURCES) libtrilogy.a
	$(CC) $(CFLAGS) $(LDFLAGS) -Wno-strict-prototypes -o test/test $(TEST_SOURCES) -L. -ltrilogy $(OPENSSL)

update_greatest:
	curl -o test/greatest.h https://raw.githubusercontent.com/silentbicycle/greatest/master/greatest.h

.PHONY: test
test: test/test
	test/test
