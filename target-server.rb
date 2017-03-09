#!/usr/bin/env ruby
require 'hexdump'
require 'socket'

class TargetServer
   
    def initialize(opts={})
   
        @address = opts[:address] ? opts[:address] : '127.0.0.1'
        @port = opts[:port] ? opts[:port] : 4444 
   
    end 
   
    def start()
        acceptor = TCPServer.open(@address, @port)
        fds = [acceptor]
        while true
            begin
                puts "Select loop"
                if ios = select(fds, [], [], 10)
                    reads = ios.first
                    reads.each do |client|
                        if client == acceptor

                            puts "New client"
                            client, sockaddr = acceptor.accept
                            fds << client

                        elsif client.eof?

                            puts "Client disconneted"
                            client.close
                            fds.delete(client)

                        else

                            handle(client)

                        end
                    end
                end
            rescue => e
                puts "Rescue"
                puts e.to_s
                puts e.backtrace.join("\n")
                
            end
        end
    end
    
    # 
    def server_packet_1
        %Q{0000001024424242424242424242424242424242}.scan(/../).map{|b| b.hex}.pack("C*")
    end

    def server_packet_2
        %Q{000000ff244242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424241}.scan(/../).map{|b| b.hex}.pack("C*")
    end
   
    def handle(client)
        payload_length = client.read(4).unpack("N")[0]
        printf("Client request payload_length 0x%08x\n", payload_length)
        pkt = client.read(payload_length)
        Hexdump.dump pkt
        
        # parse stuff here
        
        if payload_length <= 0x0f
            client.write server_packet_1
        else
            client.write server_packet_2
        end
        
        return
    end
end

ipaddr = ARGV[0] || '127.0.0.1'
server = TargetServer.new({address: ipaddr})
server.start