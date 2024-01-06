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

		print("-- Start proto.dissector -- for a Sapient Message in ")
        proto.dissector = function(tvb, pinfo, tree)
            local subtree = tree:add(proto, tvb())

            local header = 2 -- VarInt protobuf codage Base 128 !!
            local offset = 0
            local remaining_len = tvb:len()
			print("Sapient Message length + header", remaining_len)
			
			print("pinfo.fragmented = ", pinfo.fragmented)
            print("pinfo.desegment_len = ", pinfo.desegment_len)
            print("pinfo.desegment_offset = ", pinfo.desegment_offset)
            print("subtree = ", subtree)
	
            while remaining_len > 0 do
				print("-- remaining_len > 0 --")
                if remaining_len < header then -- header not enought
                    pinfo.desegment_offset = offset
                    pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
					print("-- Debug -- remaining_len < header : exit")
                    return -1
                end

                -- Get Sapient Message Size --
                local msg_len = ByteArray.new(tvb:bytes(0, header):tohex())
				print("test msg length from bytearray : ", msg_len)
                -- convert from ByteArray to Number
                local msb_msg_len = msg_len:get_index(1)
                local lsb_msg_len = msg_len:get_index(0)
                -- as explained on google protobuf Base 128 -- https://protobuf.dev/programming-guides/encoding/
                -- 1. Grab MSB 7 -> 2 Bytes with only 7 bits
                -- 2. concat MSB - LSB
                -- 3. Get the new value
                local lsb_msg_len_bit = bit.lshift(bit.band(bit.tobit(lsb_msg_len), 0x7F), 1) -- convert to bit, drop MSB 7, do a shift to left
                local msb_msg_len_bit = bit.lshift(bit.tobit(msb_msg_len), 8) -- convert to bit, shift msb to his byte position

                msg_len = bit.rshift(bit.bor(msb_msg_len_bit, lsb_msg_len_bit), 1) -- concat bit through OR operator, shift to right by 1 to drop the MSB 7 from the MSB message part
				
                msg_len = remaining_len - header
				print("-- Debug -- msg_len : ", msg_len)

                if remaining_len - header < msg_len then
                    pinfo.desegment_offset = offset
                    pinfo.desegment_len = msg_len - (remaining_len - header)
					print("-- Debug -- remaining_len - header < msg_len: exit")
                    return -1
                end
                
                subtree:add(f_length, msg_len)
                print(subtree)
                if msgtype ~= nil then
                    pinfo.private["pb_msg_type"] = "message," .. msgtype
                end
                print("Dissector.call :", Dissector.call)
                print("protobuf_dissector :", protobuf_dissector)
                print("tvb(offset, msg_len):tvb() :", tvb(offset, msg_len):tvb())
                print("offset :", offset)
                print("msg_len :", msg_len)
                print("pinfo. : ", pinfo)
                print("pinfo : ", pinfo)
                print("subtree :", subtree)
                
				local success, error_message = pcall(Dissector.call, protobuf_dissector, tvb(offset, msg_len):tvb(), pinfo, subtree)
                if  not success then
					print("Error : " .. error_message)
				end

                print("offset : ", offset, "remaining_len : ", remaining_len)
                remaining_len = remaining_len - msg_len
                print("offset : ", offset, "remaining_len : ", remaining_len)

            end -- endof while remaining > 0 do
            pinfo.columns.protocol:set(name)
        end -- endof proto.dissector = function (tvb, pinfo, tree)
        DissectorTable.get("tcp.port"):add(0, proto)
        DissectorTable.get("udp.port"):add(0, proto)
        return proto
    end -- endof function create_sapient_protobuf_dissector

    -- add more protobuf dissectors with message types
    create_sapient_protobuf_dissector("SapientMessages", "SapientMessage Sapient", "sapient_msg.SapientMessage")

end -- endof do
