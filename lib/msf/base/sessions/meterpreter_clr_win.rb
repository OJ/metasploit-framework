# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_Clr_Win < Msf::Sessions::Meterpreter
  def initialize(rstream,opts={})
    super
    self.base_platform = 'windows'
    self.base_arch = ARCH_X86 # TODO: change this 
  end

  def supports_ssl?
    false
  end
end

end
end
