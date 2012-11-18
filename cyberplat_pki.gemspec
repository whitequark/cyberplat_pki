# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |gem|
  gem.name          = "cyberplat_pki"
  gem.version       = "1.0.0"
  gem.authors       = ["Peter Zotov"]
  gem.email         = ["whitequark@whitequark.org"]
  gem.description   = %q{CyberplatPKI is an FFI binding for signing Cyberplat requests.}
  gem.summary       = gem.description
  gem.homepage      = "http://github.com/whitequark/cyberplat_pki"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.extensions    = ["ext/mock_the_clock/extconf.rb"]

  gem.add_dependency             "ffi"
  gem.add_development_dependency "rspec"
end
