# This file was generated by the `rspec --init` command. Conventionally, all
# specs live under a `spec` directory, which RSpec adds to the `$LOAD_PATH`.
# Require this file using `require "spec_helper"` to ensure that it is only
# loaded once.
#
# See http://rubydoc.info/gems/rspec-core/RSpec/Core/Configuration
RSpec.configure do |config|
  config.treat_symbols_as_metadata_keys_with_true_values = true
  config.run_all_when_everything_filtered = true
  config.filter_run :focus

  # Run specs in random order to surface order dependencies. If you find an
  # order dependency and want to debug it, you can fix the order by providing
  # the seed, which is printed after each run.
  #     --seed 1234
  config.order = 'random'
end

if RUBY_ENGINE == 'ruby' &&
      RUBY_PLATFORM =~ /i.86/
  require 'time'

  if Time.now != Time.parse('5th November 2005 00:00 UTC')
    if ENV['TIME_TRAVEL'] != '1'
      puts "Travelling back in time..."

      ENV['TIME_TRAVEL'] = '1'

      mock_path = File.expand_path('../../ext/mock_the_clock/mock_the_clock.so', __FILE__)
      exec "sh", "-c", "LD_PRELOAD=#{mock_path} #{$0}"
    else
      puts "Time machine failure, continuing."
    end
  else
    puts "Time.now: #{Time.now}"
  end
end

require 'cyberplat_pki'