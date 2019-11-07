# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'

module Msf

###
#
# Complex bind_tcp payload generation for Windows ARCH_CLR4.
#
###

module Payload::Clr4::BindTcp

  include Msf::Payload::TransportConfig
  include Msf::Payload::Clr4

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port: datastore['LPORT']
    }

    generate_bind_tcp(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def transport_config(opts={})
    transport_config_bind_tcp(opts)
  end

  #
  # Don't use IPv6 by default, this can be overridden by other payloads
  #
  def use_ipv6
    false
  end

  #
  # Generate and compile the stager
  #
  def generate_bind_tcp(opts={})
    'THIS IS WHERE THE CLR4 BIND TCP STAGER PAYLOAD GOES'
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # EXITFUNK processing adds 31 bytes at most (for ExitThread, only ~16 for others)
    space += 31

    # EXITFUNK unset will still call ExitProces, which adds 7 bytes (accounted for above)

    # Reliability checks add 4 bytes for the first check, 5 per recv check (2)
    space += 14

    space += uuid_required_size if include_send_uuid

    # The final estimated size
    space
  end

end

end

