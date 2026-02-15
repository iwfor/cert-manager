# frozen_string_literal: true

module CertManager
  # Shared helper for checking file permissions on sensitive files
  module FilePermissions
    # Warn to stderr if the file is readable by group or others
    # @param path [String] Path to the file to check
    def self.check(path)
      mode = File.stat(path).mode & 0o777
      return if mode & 0o044 == 0

      warn "\e[1;33mWARNING: #{path} is world-readable (mode #{'%04o' % mode}).\e[0m"
      warn "\e[1;33mThis file contains sensitive credentials. Fix with: chmod 600 #{path}\e[0m"
    end
  end
end
