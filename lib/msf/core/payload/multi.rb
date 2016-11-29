# -*- coding: binary -*-
require 'msf/core'

###
#
#
#
###
module Msf::Payload::Multi

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Multi-Platform Meterpreter Payload',
      'Description'   => 'Detect and generate the appropriate payload based on platform/arch',
      'Author'        => ['OJ Reeves'],
      'Platform'      => ['multi'],
      'Arch'          => ARCH_ALL,
      'Stage'         => {'Payload' => ''},
      'PayloadCompat' => {'Convention' => 'sockedi sockrdi http https'},
      ))
  end

  def resolve_stager(opts)
    uuid = opts[:payload_uuid] || opts[:uuid]
    if uuid
      c = Class.new(::Msf::Payload)
      c.include(::Msf::Payload::Stager)

      case uuid.platform
      when 'python'
        require 'msf/core/payload/python'
        c.include(::Msf::Payload::Python)
      when 'java'
          require 'msf/core/payload/java'
          c.include(::Msf::Payload::Java)
      when 'android'
        require 'msf/core/payload/android'
        c.include(::Msf::Payload::Android)
      when 'php'
        require 'msf/core/payload/php'
        c.include(::Msf::Payload::Php)
      when 'windows'
        require 'msf/core/payload/windows'
        c.include(::Msf::Payload::Windows)
      else
        return self
      end

      c.new(self.module_info)
    else
      self
    end
  end
end


