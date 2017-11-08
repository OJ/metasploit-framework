# -*- coding: binary -*-

require 'msf/core'
require 'rex/socket/x509_certificate'
require 'uri'
require 'net/http'
require 'socket'
require 'openssl'

module Msf

###
#
# Implements SSL validation check options
#
###

module Payload::Windows::VerifySsl

  #
  # Get the SSL hash from the certificate, if required.
  #
  def get_ssl_cert_hash(verify_cert, handler_cert)
    unless verify_cert.to_s =~ /^(t|y|1)/i
      return nil
    end

    unless handler_cert
      raise ArgumentError, 'Verifying SSL cert is enabled but no handler cert is configured'
    end

    hash = nil

    # check to see if a hash was given
    if handler_cert =~ /^[0-9a-f]{40}$/i
      hash = [handler_cert].pack('H*')
    elsif handler_cert =~ /^https:\/\/.*$/i
      print_status("Extracting SSL hash from #{handler_cert} ...")
      uri = URI(handler_cert)
      tcp_client = ::TCPSocket.new(uri.host, uri.port)
      ssl_client = ::OpenSSL::SSL::SSLSocket.new(tcp_client)
      ssl_client.hostname = uri.host
      ssl_client.connect
      cert = ::OpenSSL::X509::Certificate.new(ssl_client.peer_cert)
      ssl_client.sysclose
      tcp_client.close
      hash = Rex::Text.sha1_raw(cert.to_der)
    elsif ::File.exist?(::File.expand_path(handler_cert))
      hash = Rex::Socket::X509Certificate.get_cert_file_hash(handler_cert)
    else
      raise ArgumentError, 'Unable to determine SSL hash'
    end

    print_status("Meterpreter will verify SSL Certificate with SHA1 hash #{hash.unpack('H*').first}")
    hash
  end

end

end

