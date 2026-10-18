# frozen_string_literal: true

require 'openssl'
require 'base64'
require 'fileutils'
require_relative 'file_permissions'

module CertManager
  # Encrypts and decrypts individual secret values stored in the configuration
  # file, using a random key kept in a separate, owner-only key file.
  #
  # Values are stored as ENC[v1:<base64 iv+tag+ciphertext>] (AES-256-GCM).
  class SecretStore
    class Error < StandardError; end

    KEY_FILE_NAME = 'cert-manager.key'
    KEY_BYTES = 32
    IV_BYTES = 12
    TAG_BYTES = 16
    ENVELOPE = /\AENC\[v1:([A-Za-z0-9+\/=]+)\]\z/

    attr_reader :key_path

    # @param key_path [String] Path to the key file
    # @param create [Boolean] Generate the key file if it does not exist
    def initialize(key_path, create: false)
      @key_path = key_path
      self.class.generate_key(key_path) if create && !File.exist?(key_path)
      @key = load_key
    end

    # Default key file location for a config file path
    def self.key_path_for(config_path)
      File.join(File.dirname(File.expand_path(config_path)), KEY_FILE_NAME)
    end

    # Create a new key file with owner-only permissions. Never overwrites.
    def self.generate_key(path)
      FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
      File.open(path, File::CREAT | File::EXCL | File::WRONLY, 0o600) do |f|
        f.write(Base64.strict_encode64(OpenSSL::Random.random_bytes(KEY_BYTES)))
      end
      path
    end

    def self.encrypted?(value)
      value.is_a?(String) && ENVELOPE.match?(value)
    end

    def encrypted?(value)
      self.class.encrypted?(value)
    end

    # @param plaintext [String]
    # @return [String] ENC[v1:...] envelope
    def encrypt(plaintext)
      cipher = OpenSSL::Cipher.new('aes-256-gcm').encrypt
      cipher.key = @key
      iv = cipher.random_iv
      cipher.auth_data = ''
      ciphertext = cipher.update(plaintext.to_s) + cipher.final
      "ENC[v1:#{Base64.strict_encode64(iv + cipher.auth_tag + ciphertext)}]"
    end

    # @param value [String] ENC[v1:...] envelope
    # @return [String] plaintext
    def decrypt(value)
      match = ENVELOPE.match(value.to_s) or raise Error, 'Value is not an encrypted ENC[v1:...] secret'
      raw = Base64.strict_decode64(match[1])
      raise Error, 'Encrypted secret is truncated' if raw.bytesize < IV_BYTES + TAG_BYTES

      iv = raw.byteslice(0, IV_BYTES)
      tag = raw.byteslice(IV_BYTES, TAG_BYTES)
      ciphertext = raw.byteslice(IV_BYTES + TAG_BYTES..)

      cipher = OpenSSL::Cipher.new('aes-256-gcm').decrypt
      cipher.key = @key
      cipher.iv = iv
      cipher.auth_tag = tag
      cipher.auth_data = ''
      (cipher.update(ciphertext) + cipher.final).force_encoding(Encoding::UTF_8)
    rescue OpenSSL::Cipher::CipherError, ArgumentError
      raise Error, "Could not decrypt secret with #{@key_path} (wrong key or corrupted value)"
    end

    # Mask a secret for display, e.g. "****abcd"
    def self.mask(value)
      value = value.to_s
      value.length > 8 ? "****#{value[-4..]}" : '****'
    end

    private

    def load_key
      raise Error, "Key file not found: #{@key_path}" unless File.exist?(@key_path)

      FilePermissions.require_private!(@key_path)
      key = Base64.strict_decode64(File.read(@key_path).strip)
      raise Error, "Key file #{@key_path} is invalid (expected #{KEY_BYTES} bytes)" unless key.bytesize == KEY_BYTES

      key
    rescue ArgumentError
      raise Error, "Key file #{@key_path} is not valid base64"
    end
  end
end
