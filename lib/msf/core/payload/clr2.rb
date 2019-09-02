# -*- coding: binary -*-
require 'msf/core'

###
#
# This class is here to implement advanced variable substitution
# for CLR-based payloads.
#
###
module Msf::Payload::Clr2

  require 'msf/core/payload/clr2/meterpreter_loader'

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
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

end

