# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/transport_config'

module Msf

###
#
# Complex reverse_tcp_uuid payload generation for Multiple architectures
#
###

module Payload::Multi::ReverseTcpUUID

  include Msf::Payload::TransportConfig
  include Msf::Payload::Multi

  #
  # Makes no sense for us to generate the first stage
  #
  def generate(opts={})
    ''
  end

  #
  # This has to be set to true, we don't support multi-arch
  # Stagers without UUID support.
  #
  def include_send_uuid
    true
  end

  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

end

end
