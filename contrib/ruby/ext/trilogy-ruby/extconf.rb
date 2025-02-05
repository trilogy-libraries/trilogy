require "mkmf"

$objs = %w[cast.o cext.o]
$CFLAGS << " -I #{__dir__}/inc -std=gnu99 -fvisibility=hidden"

dir_config("openssl")

have_library("crypto", "CRYPTO_malloc")
have_library("ssl", "SSL_new")
have_func("rb_interned_str", "ruby.h")
root = File.expand_path(File.join(__dir__, "../../../../"))
dirs = Dir["#{root}/**/*.{a,so}"].map {|x|File.dirname(x)} | [root]
find_library("trilogy", nil, *dirs)

create_makefile "trilogy/cext"
