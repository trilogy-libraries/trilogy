require "mkmf"

# concatenate trilogy library sources to allow the compiler to optimise across
# source files
File.binwrite("trilogy.c",
  Dir["#{__dir__}/src/**/*.c"].map { |src| File.binread(src) }.join)

$objs = %w[trilogy.o cast.o cext.o]
$CFLAGS << " -I #{__dir__}/inc -std=gnu99"

dir_config("openssl")

have_library("crypto", "CRYPTO_malloc")
have_library("ssl", "SSL_new")

create_makefile "trilogy/cext"
