if set_plugin_info then
    local my_info = {
        version   = "2.0",
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

    -- Store the state between segments
    local sapient_state = {
        remaining_msg_len = 0, -- Length of the message that we are still waiting for
        is_partial_message = false, -- Flag indicating if we're in the middle of a message
        msg_len = 0 -- Total length of the message (excluding header)
    }
    -- The TCP dissector will
    local function create_sapient_protobuf_dissector(name, desc, msgtype)
        local proto = Proto(name, desc)
        local f_length = ProtoField.uint32(name .. ".length", "Sapient Message Length", base.DEC)
        proto.fields = { f_length }

        print("-- Debug -- Start proto.dissector -- for a Sapient Message in ")

        proto.dissector = function(tvb, pinfo, tree)
            local subtree = tree:add(proto, tvb())

            -- 4 Bytes which must be converted from Little Endian
            local header = 4 
            local offset = 0
            local remaining_len = tvb:len()

			print("-- Debug -- Sapient Message length + header = ", remaining_len)
			print("-- Debug -- pinfo.fragmented = ", pinfo.fragmented)
            print("-- Debug -- pinfo.desegment_len = ", pinfo.desegment_len)
            print("-- Debug -- pinfo.desegment_offset = ", pinfo.desegment_offset)
            
            -- Check if we are handling a partial message from a previous segment
            if sapient_state.is_partial_message then
                print("Handling a continuation of partial message.")

                local msg_len = sapient_state.remaining_msg_len
                
                if remaining_len < msg_len then
                    -- Not enough data, request more segments
                    pinfo.desegment_offset = offset
                    pinfo.desegment_len = msg_len - remaining_len
                    
                    print("-- Debug -- Partial message: remaining_len < msg_len, requesting more data")
                    
                    return -1
                end

                -- We have enough data to complete the message
                subtree:add(f_length, msg_len)

                -- Call the protobuf dissector to hanqdle the message
                local success, error_message = pcall(Dissector.call, protobuf_dissector, tvb(offset, msg_len):tvb(), pinfo, subtree)
                if not success then
                    print("-- Error --" .. error_message)
                end

                -- Reset state ater handling the message
                sapient_state.remaining_msg_len = 0
                sapient_state.is_partial_message = false

                offset = offset + msg_len
                remaining_len = remaining_len - msg_len
                print("-- Debug -- offset: ", offset, "remaining_len: ", remaining_len)
            end

            -- Continue with new message (starting with a header)
            while remaining_len > 0 do
				print("-- Debug -- remaining_len > 0 --")

                -- Check if we have enough bytes for the header
                if remaining_len < header then
                    pinfo.desegment_offset = offset
                    pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
					
                    print("-- Debug -- remaining_len < header : exit")
                    
                    return -1
                end

                -- Read the message length (4 bytes; little-endian)
                local msg_len = tvb(offset, header):le_uint()
                sapient_state.msg_len = msg_len -- Store the message length (excluding the header)
                print("-- Debug -- msg_len (little-endian):", msg_len)

                -- Check if there is enough data remaining to handle the message
                if remaining_len - header < msg_len then
                    -- not enough data, request more segments
                    sapient_state.remaining_msg_len = msg_len
                    sapient_msg.is_partial_message = true

                    pinfo.desegment_offset = offset + header
                    pinfo.desegment_len = msg_len - (header - remaining_len)
					
                    print("-- Debug -- remaining_len - header < msg_len: exit and store state")
                    
                    return -1
                end
                
                -- Add the message length to the subtree
                subtree:add(f_length, msg_len)

                if msgtype ~= nil then
                    pinfo.private["pb_msg_type"] = "message," .. msgtype
                end
                
                -- Call the protobuf dessector to handle the message
				local success, error_message = pcall(Dissector.call, protobuf_dissector, tvb(offset + header, msg_len):tvb(), pinfo, subtree)
                
                if  not success then
					print("Error : " .. error_message)
				end

                -- Update the remaing length of the offset for the next iteration
                offset = offset + msg_len + header
                remaining_len = remaining_len - (msg_len + header)
                print("offset : ", offset, "remaining_len : ", remaining_len)
            end -- endof while remaining > 0 do
            
            -- Set the protocol name in the Wireshark columns
            pinfo.columns.protocol:set(name)
        end -- endof proto.dissector = function (tvb, pinfo, tree)

        -- Register the dissector for both TCP qnd UDP ports
        DissectorTable.get("tcp.port"):add(0, proto)
        DissectorTable.get("udp.port"):add(0, proto)

        return proto
    end -- endof function create_sapient_protobuf_dissector

    -- Create the SapientMessages dissector with protobuf support
    create_sapient_protobuf_dissector("SapientMessages", "SapientMessage Sapient", "sapient_msg.bsi_flex_335_v2_0.SapientMessage")

end -- endof do
