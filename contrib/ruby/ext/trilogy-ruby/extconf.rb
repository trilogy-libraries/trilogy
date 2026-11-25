require "mkmf"

# concatenate trilogy library sources to allow the compiler to optimise across
# source files

trilogy_src_dir = File.realpath("src", __dir__)
File.binwrite("trilogy.c",
  Dir["#{trilogy_src_dir}/**/*.c"].map { |src|
    %{#line 1 "#{src}"\n} + File.binread(src)
  }.join)

$objs = %w[trilogy.o cast.o cext.o]
append_cflags([
  # Ref: https://github.com/trilogy-libraries/trilogy/issues/290
  # Fix build on older ruby versions and Xcode 26.4+
  "-Wno-default-const-init-field-unsafe",

  "-I#{__dir__}/inc",
  "-std=gnu99",
  "-fvisibility=hidden",
  "-DTRILOGY_XALLOCATOR",
  "-g",
])

if RUBY_PLATFORM.match?(/mingw|mswin/)
  # The Trilogy library talks to Winsock directly, using SOCKET handles. Ruby's
  # own DLL also exports recv, send, select and friends, as wrappers that expect
  # C runtime file descriptors instead, and it comes first on the link line.
  # Put Winsock ahead of it so the library binds to the real functions.
  $LOCAL_LIBS << (RUBY_PLATFORM.include?("mswin") ? " ws2_32.lib" : " -lws2_32")
end

dir_config("openssl").any? || pkg_config("openssl")

have_library("crypto", "CRYPTO_malloc")
have_library("ssl", "SSL_new")
have_func("rb_ractor_local_storage_value_newkey", "ruby.h")
have_func("rb_enc_interned_str", "ruby.h")
have_func("rb_io_descriptor", "ruby.h") # Ruby 3.1+

create_makefile "trilogy/cext"
