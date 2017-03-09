# Protocolander

This repository contains a very basic Wireshark protocol dissector written in Lua. I hope you find it useful when documenting unknown protocols. Happy protocol reversing. In addition, I have included a client and server written in Ruby. These programs are used to speak a made up protocol to each other, which the Wireshark decoder will parse. This is a very basic example to guide you learning about either Wireshark Lua protocol decoders and/or Ruby client/server protocol development. 

## Enabling target_protocol.lua in Wireshark

Make sure the Wireshark Lua init file ${HOME}/.wireshark/init.lua contains a command to load your protocol parser.

dofile(os.getenv("HOME") .. "/protocolander/target_protocol.lua")

## Setting default port

The current example shows setting a default TCP port of 4444 for the dissector. You should change this value according to your target.

## Included Client and Server

There are two Ruby scripts in the repo to act as the client and server of a made up protocol. You can use the target_protocol.lua dissector to dissect this protocol in Wireshark. This can serve as a playground for people to learn about both writing protocols and dissecting their network packets.

