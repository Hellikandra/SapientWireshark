if set_plugin_info then
    local my_info = {
        version   = "1.0",
        author    = "Jean Vanhay",
        email     = "jean.vanhay@gmail.com",
        copyright = "",
        license   = "MIT license",
        details   = "This is a Lua plugin for Wireshark, to dissect SAPIENT using Google protobuf messages.",

    }
    set_plugin_info(my_info)
end
do
    local protobuf_dissector = Dissector.get("protobuf")
    -- The TCP dissector will
    local function create_sapient_protobuf_dissector(name, desc, msgtype)
        local proto = Proto(name, desc)
        local f_length = ProtoField.uint32(name .. ".length", "Sapient Message Length", base.DEC)
        proto.fields = { f_length }

        proto.dissector = function(tvb, pinfo, tree)
            local subtree = tree:add(proto, tvb())

            local header = 2 -- VarInt protobuf codage Base 128 !!
            local offset = 2
            local remaining_len = tvb:len()
    
            while remaining_len > 0 do
                if remaining_len < header then -- header not enought
                    pinfo.desegment_offset = offset
                    pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                    return -1
                end

                -- Get Sapient Message Size --
                local msg_len = ByteArray.new(tvb:bytes(0, header):tohex())
                -- convert from ByteArray to Number
                local msb_msg_len = msg_len:get_index(1)
                local lsb_msg_len = msg_len:get_index(0)
                -- as explained on google protobuf Base 128
                -- 1. Grab MSB 7 -> 2 Bytes with only 7 bits
                -- 2. concat MSB - LSB
                -- 3. Get the new value
                local lsb_msg_len_bit = bit.lshift(bit.band(bit.tobit(lsb_msg_len), 0x7F), 1) -- convert to bit, drop MSB 7, do a shift to left
                local msb_msg_len_bit = bit.lshift(bit.tobit(msb_msg_len), 8) -- convert to bit, shift msb to his byte position

                msg_len = bit.rshift(bit.bor(msb_msg_len_bit, lsb_msg_len_bit), 1) -- concat bit through OR operator, shift to right by 1 to drop the MSB 7 from the MSB message part

                if remaining_len - header < msg_len then
                    pinfo.desegment_offset = offset
                    pinfo.desegment_len = msg_len - (remaining_len - header)
                    return -1
                end
                
                subtree:add(f_length, msg_len)

                if msgtype ~= nil then
                    pinfo.private["pb_msg_type"] = "message," .. msgtype
                end

                pcall(Dissector.call, protobuf_dissector, tvb(offset, msg_len):tvb(), pinfo, subtree)

                offset = offset + header + msg_len
                remaining_len = remaining_len - header

            end -- endof while remaining > 0 do
            pinfo.columns.protocol:set(name)
        end -- endof proto.dissector = function (tvb, pinfo, tree)
        DissectorTable.get("tcp.port"):add(0, proto)
        DissectorTable.get("udp.port"):add(0, proto)
        return proto
    end -- endof function create_sapient_protobuf_dissector

    -- add more protobuf dissectors with message types
    create_sapient_protobuf_dissector("SapientMessages", "SapientMessage Sapient", "sapient.SapientMessage")

end -- endof do
