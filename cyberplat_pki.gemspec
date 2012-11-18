# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |gem|
  gem.name          = "cyberplat_pki"
  gem.version       = "2.0.2"
  gem.authors       = ["Peter Zotov"]
  gem.email         = ["whitequark@whitequark.org"]
  gem.description   = %q{CyberplatPKI is a library for signing Cyberplat requests.}
  gem.summary       = gem.description
  gem.homepage      = "http://github.com/whitequark/cyberplat_pki"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.extensions    = ["ext/mock_the_clock/extconf.rb"]

  gem.add_development_dependency "rspec"
  gem.add_dependency 'digest-crc' # For CRC24
  gem.add_dependency 'crypt'      # For IDEA
  gem.add_dependency "jruby-openssl" if RUBY_PLATFORM == "java"
  gem.add_dependency "openssl" if RUBY_PLATFORM == "ruby"
end
