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
        %Q{0000001025004141414141414141414141414141}.scan(/../).map{|b| b.hex}.pack("C*")
    end

    def client_packet_2
        %Q{000000ff260041414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141}.scan(/../).map{|b| b.hex}.pack("C*")
    end
    
    def client_packet_3_f0
        %Q{000000ff270041414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141}.scan(/../).map{|b| b.hex}.pack("C*")
    end

    def client_packet_request_bytes(length)
        pktlen = 0x08
        type = 0x24
        [pktlen, type, length].pack("NNN")
    end


    def connect
        rand = Random.new
        @socket = TCPSocket.new(@server, @port)
        while true
            @socket.write client_packet_1
            handle(@socket)
            sleep 0.5
            
            @socket.write client_packet_2
            handle(@socket)
            sleep 0.5
            
            @socket.write client_packet_3_f0
            handle(@socket)
            sleep 1.0
            
            requested_length = rand.rand(0x40000)
            STDERR.printf("Client requests 0x%08x bytes\n", requested_length)
            @socket.write client_packet_request_bytes(requested_length)
            handle(@socket)
            
            sleep 2            
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