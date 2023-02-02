local udpnm_plugin_info =
{
	version = "0.0.1",
	description = "This plugin parses the UDP-NM"
}

set_plugin_info(udpnm_plugin_info)

udpnm_protocol = Proto("UdpNM", "UDP-NM Protocol")

-- Header fields
proto_SourceNodeIdentifier_1byte   = ProtoField.uint8 ("udpnm_protocol.SourceNodeIdentifier", "Source Node Identifier", base.HEX)
proto_ControlBitVector_1byte       = ProtoField.uint8 ("udpnm_protocol.ControlBitVector", "Control Bit Vector", base.HEX)
--[Control Bit Vector]
--RepeatMessageRequest_1bit
--PNShutdownRequest_1bit
--Reserved1_1bit
--NMCoordinatorSleepReady_1bit
--ActiveWakeup_1bit
--PNLearning_1bit
--PNInformation_1bit
--Reserved2_1bit
proto_PNInfo_6bytes                = ProtoField.bytes ("udpnm_protocol.PNInfo", "PN Info", base.NONE)

udpnm_protocol.fields = { proto_SourceNodeIdentifier_1byte, proto_ControlBitVector_1byte, proto_PNInfo_6bytes }


local function heuristic_checker(buffer, pinfo, tree)
    -- guard for length
    length = buffer:len()
    --print(string.format("UDP payload length : %d", length))

	-- buffer(0,8) means from buf 0 to buf 7, total 8 bytes
    --local UdpNM_8Bytes = buffer(0,8):uint()

	-- T UdpNM is 8 bytes
    if length == 8
    then
        udpnm_protocol.dissector(buffer, pinfo, tree)
        return true
    else return false end
end

function udpnm_protocol.dissector(buffer, pinfo, tree)
    --length = buffer:len()
    --if length ~= 8 then return end

    pinfo.cols.protocol = udpnm_protocol.name

    local subtree = tree:add(udpnm_protocol, buffer(), "UDP-NM Protocol(T format : 8 bytes)")

    -- Header
    local __comment__ = "1 byte"
    subtree:add(proto_SourceNodeIdentifier_1byte, buffer(0,1)):append_text(" (" .. __comment__ .. ")")
    local subsub_ControlBitVector = subtree:add(proto_ControlBitVector_1byte, buffer(1,1)):append_text(" (" .. __comment__ .. ")")

    local bit7 = bit.rshift(bit.band(buffer(1,1):uint(), 0x80), 7)
    local bit6 = bit.rshift(bit.band(buffer(1,1):uint(), 0x40), 6)
    local bit5 = bit.rshift(bit.band(buffer(1,1):uint(), 0x20), 5)
    local bit4 = bit.rshift(bit.band(buffer(1,1):uint(), 0x10), 4)
    local bit3 = bit.rshift(bit.band(buffer(1,1):uint(), 0x08), 3)
    local bit2 = bit.rshift(bit.band(buffer(1,1):uint(), 0x04), 2)
    local bit1 = bit.rshift(bit.band(buffer(1,1):uint(), 0x02), 1)
    local bit0 = bit.band(buffer(1,1):uint(), 0x01)
    --print(string.format("bit7~0 : %x %x %x %x %x %x %x %x", bit7, bit6, bit5, bit4, bit3, bit2, bit1, bit0))
    subsub_ControlBitVector:add(buffer(1,1), "Repeat Message Request"):prepend_text("".. bit7 .. "... .... = "):append_text("(" .. bit7 .. ")")
    subsub_ControlBitVector:add(buffer(1,1), "PN Shutdown Request"):prepend_text("." .. bit6 .. ".. .... = "):append_text("(" .. bit6 .. ")")
    subsub_ControlBitVector:add(buffer(1,1), "Reserved"):prepend_text(".." .. bit5 .. ". .... = "):append_text("(" .. bit5 .. ")")
    subsub_ControlBitVector:add(buffer(1,1), "NM Coordinator Sleep Ready"):prepend_text("..." .. bit4 .. " .... = "):append_text("(" .. bit4 .. ")")
    subsub_ControlBitVector:add(buffer(1,1), "Active Wakeup"):prepend_text(".... " .. bit3 .. "... = "):append_text("(" .. bit3 .. ")")
    subsub_ControlBitVector:add(buffer(1,1), "PN Learning"):prepend_text(".... ." .. bit2 .. ".. = "):append_text("(" .. bit2 .. ")")
    subsub_ControlBitVector:add(buffer(1,1), "PN Information"):prepend_text(".... .." .. bit1 .. ". = "):append_text("(" .. bit1 .. ")")
    subsub_ControlBitVector:add(buffer(1,1), "Reserved"):prepend_text(".... ..." .. bit0 .. " = "):append_text("(" .. bit0 .. ")")

    __comment__ = "6 bytes"
    subtree:add_le(proto_PNInfo_6bytes, buffer(2,6)):append_text(" (" .. __comment__ .. ")")


end

udpnm_protocol:register_heuristic("udp", heuristic_checker)


----------------------------------------------------------------------------------------
--bit.band()         --与
--bit.bor()          --或
--bit.bxor()         --异或
--bit.lshift(a,b)    --返回a向左偏移到b位
--bit.rshift(a,b)    --返回a逻辑右偏到b位
--bit.mod(a,b)       --返回a除以b的整数余数 
--eg:
--print(bit.lshift(12,12))
--12二进制表示为00001100,向左偏移12位,则为00001100000000000000,相当于2^15+2^14,返回98304
