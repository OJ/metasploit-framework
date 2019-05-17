# -*- coding: binary -*-
require 'msf/core'

###
#
# This class is here to implement advanced variable substitution
# for CLR-based payloads, such as CLRVERSION.
#
###
module Msf::Payload::Clr

  require 'msf/core/payload/clr/meterpreter_loader'

  #
  # Implement payload prepends for Windows payloads
  #
  def apply_prepends(raw)
    raw
  end

  #
  # We don't have intermediate stages for the CLR payloads, so we are just
  # going to return the length of the full stage.
  #
  def handle_intermediate_stage(conn, payload)
    conn.put([payload.length].pack('V'))
    return false
  end

  #
  # This mixin is chained within payloads that target the CRL.
  # It provides special variable substitution for things like CLRVERSION.
  #
  def initialize(info = {})
    ret = super(info)

    register_options(
      [
        Msf::OptEnum.new('CLRVERSION', [true, 'Version of the CLR to target.', 'net35', ['net35', 'net40']])
      ])
    ret
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

end

