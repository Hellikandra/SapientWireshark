do
    local protobuf_dissector = Dissector.get("protobuf")
    -- Ctrl + Maj + L = Reload lua package
    -- Create protobuf dissector based on UDP or TCP.
    -- The UDP dissector will take the whole tvb as a message.
    -- The TCP dissector will parse tvb as format:
    --         [4bytes length][a message][4bytes length][a message]...
    -- @param name  The name of the new dissector.
    -- @param desc  The description of the new dissector.
    -- @param for_udp  Register the new dissector to UDP table.(Enable 'Decode as')
    -- @param for_tcp  Register the new dissector to TCP table.(Enable 'Decode as')
    -- @param msgtype  Message type. This must be the root message defined in your .proto file.
    local function create_protobuf_dissector(name, desc, for_udp, for_tcp, msgtype)
        local proto = Proto(name, desc)
        local f_length = ProtoField.uint32(name .. ".length", "Length", base.DEC)
        proto.fields = { f_length }

        proto.dissector = function(tvb, pinfo, tree)
            local subtree = tree:add(proto, tvb())
            if for_udp and pinfo.port_type == 3 then -- UDP
                if msgtype ~= nil then
                    pinfo.private["pb_msg_type"] = "message," .. msgtype
                end
                pcall(Dissector.call, protobuf_dissector, tvb, pinfo, subtree)
            elseif for_tcp and pinfo.port_type == 2 then -- TCP
                
                print("we are in tcp mode for sapient protobuf. It is a test message")
                local header = 2 -- Message Farming / Structure - VarInt value
                local remaining_len = tvb:len() - header -- Sapient message
                print("header : ", header, " and remaining_len : ", remaining_len)

                -- extract the header size message --
                if remaining_len > header then
                    local header_size = ByteArray.new(tvb:bytes(0, header):tohex())
                    local lsb_header = header_size:get_index(0)
                    local msb_header = header_size:get_index(1)
                    print("-- 1 -- HEADER : ", header_size, "lsb : ",lsb_header, "msb : ", msb_header)
                    print("-- 1 -- HEADER : ", type(header_size), "lsb : ", type(lsb_header), "msb : ", type(msb_header))
                    local lsb_header_bit = bit.lshift(bit.band(bit.tobit(lsb_header), 0x7F),1)
                    local msb_header_bit = bit.lshift(bit.tobit(msb_header), 8)
                    print("-- 2 -- MSB : ", msb_header_bit, "LSB : ", lsb_header_bit)
                    local header_bit = bit.bor(msb_header_bit, lsb_header_bit)
                    print("-- 3 -- HEADER Bit", header_bit)
                    header_bit = bit.rshift(header_bit, 1)
                    print("-- 4 -- Header FINAL : ", header_bit)
                else
                    return -1
                end
                -- extract the sapient message --
                local proto_head_offset = 2
                local tmp_remaining_len = tvb:len()
                
                while tmp_remaining_len > 0 do
                    if tmp_remaining_len < 2 then -- head not enough
                        print("sapient_protobuf_dessicator_work.lua")
                        pinfo.desegment_offset = proto_head_offset
                        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                        return -1
                    end
                    print("decode the next part of the message, tmp_remaining_len: ", tmp_remaining_len)
                    -- Get the size of the message --

                    -- local data_len = tvb(0, proto_head_offset):le_uint()
                    local header_size = ByteArray.new(tvb:bytes(0, header):tohex())
                    local lsb_header = header_size:get_index(0)
                    local msb_header = header_size:get_index(1)
                    -- print("-- 1 -- HEADER : ", header_size, "lsb : ",lsb_header, "msb : ", msb_header)
                    -- print("-- 1 -- HEADER : ", type(header_size), "lsb : ", type(lsb_header), "msb : ", type(msb_header))
                    local lsb_header_bit = bit.lshift(bit.band(bit.tobit(lsb_header), 0x7F),1)
                    local msb_header_bit = bit.lshift(bit.tobit(msb_header), 8)
                    -- print("-- 2 -- MSB : ", msb_header_bit, "LSB : ", lsb_header_bit)
                    local header_bit = bit.bor(msb_header_bit, lsb_header_bit)
                    -- print("-- 3 -- HEADER Bit", header_bit)
                    header_bit = bit.rshift(header_bit, 1)
                    -- print("-- 4 -- Header FINAL : ", header_bit)
                    data_len = header_bit
                    print("data_len : ", data_len)

                    -- print("tvb(proto_head_offset, 4) : ", tvb(proto_head_offset, 4))
                    
                    if tmp_remaining_len - 2 < data_len then -- data not enough
                        print("data not enough")
                        pinfo.desegment_offset = proto_head_offset
                        pinfo.desegment_len = data_len - (tmp_remaining_len - 2)
                        print(pinfo.desegment_offset, "and ", pinfo.desegment_len)
                        return -1
                    end
                    print("we have tested the data not enough")

                    subtree:add(f_length, header_bit)
                    print(subtree)

                    if msgtype ~= nil then
                        pinfo.private["pb_msg_type"] = "message," .. msgtype
                    end
                    pcall(Dissector.call, protobuf_dissector, tvb(proto_head_offset, data_len):tvb(), pinfo, subtree)
                    print("offset : ", proto_head_offset, "remaining_len : ", tmp_remaining_len)
                    proto_head_offset = proto_head_offset + 2 + data_len
                    tmp_remaining_len = tmp_remaining_len - 2
                    print("offset : ", proto_head_offset, "remaining_len : ", tmp_remaining_len)
                end
            end
            pinfo.columns.protocol:set(name)
        end -- endof proto.dissector = function(tvb, pinfo, tree)

        if for_udp then DissectorTable.get("udp.port"):add(0, proto) end
        if for_tcp then DissectorTable.get("tcp.port"):add(0, proto) end
        return proto
    end -- endof local function create_protobuf_dissector

    -- default pure protobuf udp and tcp dissector without message type
    create_protobuf_dissector("protobuf_sapient_udp", "Protobuf UDP")
    create_protobuf_dissector("protobuf_sapient_tcp", "Protobuf TCP")
    -- add more protobuf dissectors with message types
    create_protobuf_dissector("SapientProtobufMessages", "SapientMessage Sapient - Work",
                              true, true, "sapient.SapientMessage")
end

-- ------- --
-- SANDBOX --
-- ------- --
-- local lsb_header = ByteArray.new(tvb:bytes(0, 1):tohex())
-- local msb_header = ByteArray.new(tvb:bytes(1, 1):tohex())
-- print("-- 1 -- HEADER : MSB : ", msb_header, " LSB : ", lsb_header)
-- print("-- 1 -- HEADER : MSB : ", type(msb_header), " LSB : ", type(lsb_header))
-- -- lsb_header = bit.bor(bit.tobit(lsb_header), 0x80)
-- print("-- 2 -- HEADER : MSB : ", msb_header, " LSB : ", lsb_header)
-- -- lsb_header = bit.lshift(lsb_header, 1)
-- print("-- 3 -- HEADER : MSB : ", msb_header, " LSB : ", lsb_header)
-- msb_header:append(lsb_header)
-- print("-- 2 -- HEADER FINAL : ", msb_header)

-- local tutu_test = ByteArray.new("AA 01 02")
-- print("tutu_test : ", tutu_test, " et ", type(tutu_test))
-- local toto_test = tutu_test:tohex()
-- print("toto_test : ", toto_test, " et ", type(toto_test))
-- -- local titi_test = tutu_test:get_index(0)
-- local titi_test = lsb_header:get_index(0)
-- print("titi_test : ", titi_test, " et ", type(titi_test))
-- local tete_test = bit.tobit(titi_test)
-- print("tete_test : ", tete_test, " et ", type(tete_test))
-- local tata_test = bit.band(titi_test, 0x7F)

-- print("tata_test : ", tata_test, " et ", type(tata_test))
-- tata_test = bit.lshift(tata_test, 1)
-- print("tata_test : ", tata_test, " et ", type(tata_test))
-- local header_test = ByteArray.new(tvb:bytes(0, header-1):tohex())
-- print("-- 1 -- Header", header_test)
-- local lsb_header = header_test:get_index(0)
-- print("-- 2 -- Header", lsb_header)
-- lsb_header = lsb_header - 128 -- drop MSB Bit 7
-- print("-- 3 -- LSB Header", lsb_header)
-- lsb_header = bit.lshift(lsb_header, 1) -- shift to prepare concat or append
-- print("-- 4 -- LSB Header", lsb_header)
-- local msb_header = header_test:get_index(1)
-- print("-- 5 -- MSB Header", msb_header)

-- print("-- 6 -- Header", msb_header)


-- local empty = ByteArray.new()
-- print("header : ", tvb(0, header):le_uint())
-- header_bytes = tvb:bytes(0,header)
-- print("header bytes : ", header_bytes)
-- print("header bytes[0]", header_bytes:get_index(0))
-- print("header bytes[1]", header_bytes:get_index(1))
-- if header_bytes:get_index(0) > 127 then
--     print("we need to use minus the value")
--     msb_drop_0 = header_bytes:get_index(0) - 128
--     print(msb_drop)
-- else
--     msb_drop_0 = header_bytes:get_index(0)
--     print("we do not need to minus the value")
-- end
-- if header_bytes:get_index(1) > 127 then
--     msb_drop_1 = header_bytes:get_index(1) - 128
-- else
    
--     msb_drop_1 = header_bytes:get_index(1)
--     -- empty = 
--     empty = header_bytes:get_index(1) + header_bytes:get_index(0)
-- end
-- print("value of header : ", empty)
-- empty = bit.lshift(empty, 1)
-- print(empty)
-- test_1 = bit.lshift(header_bytes:get_index(1), 1)
-- print(test_1)
-- print("test : MSB : ", header_bytes:get_index(1))
-- print("test : LSB : ", header_bytes:get_index(0))
-- print("test : LSB Drop", (header_bytes:get_index(0) - 128))
-- print("test : LSB shift : ", bit.lshift((header_bytes:get_index(0) - 128), 1))
-- test_final = bit.rshift(header_bytes:get_index(1) + bit.lshift(header_bytes:get_index(0) - 128, 1), 1) -- need to do a concat and not a +

-- print("Header new value after lshift, rshift : ", test_final)
-- local tutu = ByteArray.new("01")

-- local toto = ByteArray.new("02")
-- tutu:append(toto)
-- local titi = tutu
-- print("test append : ",titi, " with tutu : ", tutu, " with toto : ", toto)

-- print("test concat : ", titi:tohex())
-- local header_final = ByteArray.new()
-- print("header msb :", header_bytes:get_index(1))
-- local msb_header = header_bytes:get_index(1)
-- print(msb_header)
-- -- print(msb_header:tohex())
-- print(header_bytes)
-- local ruru = ByteArray.new(header_bytes:tohex())
-- print("ruru : ", ruru)
-- print("ruru : ", ruru:len())
-- print("ruru : ", ruru:get_index(0))
-- local susu = ruru:get_index(0)
-- print(susu)
-- header_final:append(susu)
-- print("header final : ", header_final)
-- header_final:append(bit.lshift(header_bytes:get_index(0) - 128, 1))
-- header_final = bit.rshift(header_final, 1)
-- print(header_final)
-- extract Sapient Message
-- print("remaining_len : ", remaining_len)
-- local data_len = tvb(header):len()
-- print("data_len : ", data_len)
-- print(tvb)
-- print("header : ", tvb(header))
-- print("header : ", tvb(0, header))

-- subtree:add(f_length, tvb(header, 4))
-- print("f_length : ", f_length)
-- if msgtype ~= nil then
--     pinfo.private["pb_msg_type"] = "message" .. msgtype
-- end
-- pcall(Dissector.call, protobuf_dissector, tvb(header, data_len):tvb(), pinfo)
-- print("msgtype : ", msgtype)