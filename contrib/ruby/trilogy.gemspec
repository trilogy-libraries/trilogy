require File.expand_path("../lib/trilogy/version", __FILE__)

# ext/trilogy-ruby/inc and ext/trilogy-ruby/src are symlinks to the C library at
# the repository root. Git on Windows checks symlinks out as small text files
# holding the link target unless core.symlinks is enabled, and the globs below
# then find no C sources. Recreate any link that is not a working directory.
%w[inc src].each do |name|
  link = File.expand_path("../ext/trilogy-ruby/#{name}", __FILE__)
  next if File.directory?(link)

  relative_target = "../../../../#{name}"
  target = File.expand_path(relative_target, File.dirname(link))
  next unless File.directory?(target) # not in a repository checkout

  # Whatever is there is not a usable directory: Git's placeholder file, or a
  # file-type symlink (Git on Windows creates those when the target does not
  # exist yet at checkout), which cannot point at a directory. Replace it.
  begin
    File.delete(link)
  rescue Errno::ENOENT
    # nothing to replace
  rescue SystemCallError
    Dir.rmdir(link) # dangling directory symlink or junction
  end

  if Gem.win_platform?
    # Ruby's File.symlink resolves a relative target against the current
    # directory when deciding between a file and a directory link, so it would
    # create a file-type link here that cannot be traversed. A directory
    # junction always works and needs neither Developer Mode nor admin rights.
    system("cmd", "/c", "mklink", "/J", link.tr("/", "\\"), target.tr("/", "\\"), out: File::NULL)
  else
    File.symlink(relative_target, link)
  end

  abort "trilogy.gemspec: could not link #{link} to #{target}." unless File.directory?(link)
end

Gem::Specification.new do |s|
  s.name = "trilogy"
  s.version = Trilogy::VERSION
  s.authors = ["GitHub Engineering"]
  s.email = "opensource+trilogy@github.com"
  s.license = "MIT"
  s.homepage = "https://github.com/trilogy-libraries/trilogy"
  s.summary = "A friendly MySQL-compatible library for Ruby, binding to libtrilogy"

  s.extensions = "ext/trilogy-ruby/extconf.rb"

  gem_files = %w[LICENSE README.md Rakefile trilogy.gemspec]
  gem_files += Dir.glob("lib/**/*.rb")
  gem_files += Dir.glob("ext/trilogy-ruby/*.c")
  gem_files += Dir.glob("ext/trilogy-ruby/*.h")
  gem_files += Dir.glob("ext/trilogy-ruby/src/**/*.c")
  gem_files += Dir.glob("ext/trilogy-ruby/inc/**/*.h")

  s.files = gem_files

  s.require_paths = ["lib"]

  s.required_ruby_version = ">= 3.0"

  s.add_dependency "bigdecimal"
end
