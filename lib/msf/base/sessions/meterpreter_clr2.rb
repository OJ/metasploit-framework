# -*- coding: binary -*-

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_Clr2 < Msf::Sessions::Meterpreter
  def initialize(rstream, opts={})
    super
    self.base_platform = 'windows'
    self.base_arch = ARCH_CLR2
  end

  def supports_ssl?
    false
  end
  
  def binary_suffix
    ["net35.dll"]
  end

  # TODO: remove this once we've supported ZLIB
  def supports_zlib?
    false
  end
end

end
end
