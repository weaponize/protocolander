-- Example wireshark dissector
-- 

target_proto = Proto("target","Target Protocol")

-- Defining the fields 
local target_length             = ProtoField.uint32("target.len", "Length", base.HEX)
local target_static1            = ProtoField.uint8("target.static1", "Static Field", base.HEX)
local target_direction          = ProtoField.uint8("target.direction", "Direction", base.HEX)
local target_opcode             = ProtoField.uint8("target.type", "Opcode", base.HEX)
local target_opcode_option      = ProtoField.uint8("target.option", "Opcode Opt", base.HEX)
local target_subtype            = ProtoField.uint8("target.subtype", "Subtype", base.HEX)
local target_seq                = ProtoField.uint8("target.seq", "Sequence number", base.HEX)
local target_data               = ProtoField.bytes("target.data", "Data")
local target_static2            = ProtoField.uint8("target.static2", "Static Field", base.HEX)
local target_crc                = ProtoField.uint8("target.chk", "CRC", base.HEX)

-- 
-- example I followed said not to do the fields like this, risk of missing some
target_proto.fields = {
    target_length,
    target_static1,
    target_direction,
    target_opcode,
    target_opcode_option,
    target_subtype,
    target_seq,
    target_data,
    target_static2,
    target_crc    
}

-- protocol dissector function
function target_proto.dissector(tvbuf,pinfo,tree)

	-- set the protocol column based on the Proto object
	pinfo.cols.protocol = target_proto.description
    
    local subtree = tree:add(target_proto, tvbuf:range(0, pktlen))

	-- length of the received packet
	local pktlen = tvbuf:reported_length_remaining()
    if pktlen < 9 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet " .. pinfo.number .. " too small")
    end
        
    -- current read offset
    local offset = 0 

    --  dummy vars to parse values into for tree insertion
    local trglength        
    local static1       
    local direction     
    local opcode        
    local opcode_option 
    local subtype       
    local seq           
    local data          
    local static2       
    local crc           

    -- this parse presumes that at least 10 bytes in total
    -- TODO actually test the length maybe
    trglength = tvbuf:range(offset, 4)
    subtree:append_text(string.format(" pktlen=0x%08x, len=0x%08x", pktlen, trglength:uint()))
    subtree:add(target_length, trglength)
    offset = offset + 4
    
    -- handle message fragmentation here
    if trglength:uint() + 4 > pktlen then
        -- full message not yet received
        pinfo.desegment_len = trglen - 4 - pktlen -- int underflow here
        return
    end
    
    
    static1 = tvbuf:range(offset, 1)
    subtree:add(target_static1, static1)
    offset = offset + 1

    direction = tvbuf:range(offset, 1)
    subtree:add(target_direction, direction)
    offset = offset + 1

    opcode = tvbuf:range(offset, 1)
    subtree:add(target_opcode, opcode)
    offset = offset + 1

    opcode_option = tvbuf:range(offset, 1)
    subtree:add(target_opcode_option, opcode_option)
    offset = offset + 1

    subtype = tvbuf:range(offset, 1)
    subtree:add(target_subtype, subtype)
    offset = offset + 1

    -- this sequence number might better be considered poart of target_data
    -- also, this is not likely a 'sequence number' but something else
    -- the server uses the value of this field in responses
    if trglength:uint() >= 9 then
        seq = tvbuf:range(offset, 1)
        subtree:add(target_seq, seq)
        offset = offset + 1
    end
        
    -- this length check insures that we only populate the data member for
    -- packets that are long enough to have data
    -- the data field is unparsed but definitely where the magic happens
    if trglength:uint() > 10 then
        -- variable byte length
        local datalen = pktlen - offset - 2
        data = tvbuf:range(offset,  datalen)
        subtree:add(target_data, data)
        offset = offset + datalen
    end
    
    -- target_three and target_crc are always present
    static2 = tvbuf:range(offset, 1)
    subtree:add(target_static2, static2)
    offset = offset + 1
    
    crc = tvbuf:range(offset, 1)
    subtree:add(target_crc, crc)
    offset = offset + 1

    pinfo.cols['info'] = "Payload length: " .. trglength .. " CRC: " .. crc
    
    return
end


-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol tcp:4444
tcp_table:add(4444,target_proto)

-- Preferences
-- Currently unused
target_proto.prefs.print = Pref.bool("Print parsing", false, "Enable printing of Target Protocol")
