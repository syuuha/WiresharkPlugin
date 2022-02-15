-- Dump 1722 h.264 payload to raw h.264 file (*.264)
-- According to RFC3984 to dissector H264 payload of 1722 to NALU, and write it to *.264 file. 
-- By now, we support single NALU, STAP-A and FU-A format RTP payload for H.264.
-- You can access this feature by menu "Tools"
-- Author: Huang Qiangxiong (qiangxiong.huang@gmail.com)
-- Modify by Yang Xing (hongch_911@126.com)
--
-- Modify by zhoubo 20211027 :
--   new for 1722(payload : CVF H.264)
--   support Single NALU(1-23), FU-A(28)
--   Yang Xing's original code : automatically insert SPS and PPS in the header of the raw stream
--        so, there are twice SPS&PPS at least, 
--        binary queue : SPS[insert], PPS[insert], frame1, frame2, ..., SPS, PPS, frameX, ...
--
-- Modify by zhoubo 20211105 : 
--   support STAP-A(24)
--
-- !!! fix your own dumppath first !!!
--
------------------------------------------------------------------------------------------------
-- Wireshark’s Lua API Reference Manual
-- https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html
-- Example: Listener written in Lua
-- https://www.wireshark.org/docs/wsdg_html_chunked/wslua_tap_example.html
-- Wireshark dissector Plugin
-- https://yoursunny.com/t/2008/Wireshark-Lua-dissector/
------------------------------------------------------------------------------------------------


do
    local version_str = string.match(_VERSION, "%d+[.]%d*")
    local version_num = version_str and tonumber(version_str) or 5.1
    local bit = (version_num >= 5.2) and require("bit32") or require("bit")

    -- for geting ieee1722 data (the field's value is type of ByteArray)
    -- local proto_1722 = Proto("ieee1722","IEEE1722");

    -- local p1722_payload_subtype = ProtoField.none("ieee1722.subtype", "AVTP Subtype")
    -- local p1722_payload_svfield = ProtoField.none("ieee1722.svfield", "AVTP Stream ID Valid")
    -- local p1722_payload_verfield = ProtoField.none("ieee1722.verfield", "AVTP Version")

    -- local p1722_payload_cvf_mrfield = ProtoField.none("cvf.mrfield", "Media Clock Restart")
    -- local p1722_payload_cvf_tvfield = ProtoField.none("cvf.tvfield", "Source Timestamp Valid")
    -- local p1722_payload_cvf_seqnum = ProtoField.none("cvf.seqnum", "Sequence Number")
    -- local p1722_payload_cvf_tufield = ProtoField.none("cvf.tufield", "Timestamp Uncertain")
    -- local p1722_payload_cvf_stream_id = ProtoField.none("cvf.stream_id", "Stream ID")
    -- local p1722_payload_cvf_avtp_timestamp = ProtoField.none("cvf.avtp_timestamp", "AVTP Timestamp")
    -- local p1722_payload_cvf_format = ProtoField.none("cvf.format", "Format")
    -- local p1722_payload_cvf_format_subtype = ProtoField.none("cvf.format_subtype", "CVF Format Subtype")
    -- local p1722_payload_cvf_stream_data_len = ProtoField.none("cvf.stream_data_len", "Stream Data Length")
    -- --local 1722_payload_cvf_h264_ptvfield = ProtoField.none("cvf.h264_ptvfield", "H264 Payload Timestamp Valid")
    -- local p1722_payload_cvf_marker_bit = ProtoField.none("cvf.marker_bit", "Marker Bit")
    -- local p1722_payload_cvf_EVT = ProtoField.none("cvf.evtfield", "EVT")
    -- local p1722_payload_cvf_h264_timestamp = ProtoField.none("cvf.mrfield", "H264 Timestamp")

    -- local p1722_payload_cvf_h264payload = ProtoField.none("h264.nalu_payload", "Raw")

    -- proto_1722.fields = {
    --     p1722_payload_subtype, p1722_payload_svfield, p1722_payload_verfield,
    --     p1722_payload_cvf_mrfield, p1722_payload_cvf_tvfield, p1722_payload_cvf_seqnum, p1722_payload_cvf_tufield,
    --         p1722_payload_cvf_stream_id, p1722_payload_cvf_avtp_timestamp, p1722_payload_cvf_format, p1722_payload_cvf_format_subtype,
    --         p1722_payload_cvf_stream_data_len, p1722_payload_cvf_marker_bit, p1722_payload_cvf_EVT, p1722_payload_cvf_h264_timestamp,  
    --     p1722_payload_cvf_h264payload
    -- }

    -- local 1722_stream_type_vals = {
    --     [0x10] = "IEEE 1722 Audio Video Transport Protocol (AVTP)",
    --     [0x1b] = "IEC 61883 Protocol",
    --     [0x24] = "AVTP Audio Format", --aaf
    --     [0x08] = "AVTP Compressed Video Format", --cvf
    --     [0x08] = "Clock Reference Format", --crf
    --     [0x800] = "Non-Time-Synchronous Control Format", --ntscf
       -- [0x08] = "Time-Synchronous Control Format", --tscf
       -- [0xFE00] = "ACF Message", --acf
       -- [0xC0] = "ACF CAN", --acf-can
       -- [0xC0] = "ACF LIN", --acf-lin
    -- }


    local f_ieee1722 = Field.new("ieee1722")
    --local f_h264 = Field.new("h264")

    local tw1722 -- TextWindow, window for showing information and debug msg
    local pgtw1722 -- ProgDlg

    -- add message to information window
    function twappend(str)
        tw1722:append(str)
        tw1722:append("\n")
    end

	local function str2hex(str)
	    str = string.gsub(str,"(.)",function (x) return string.format("%02X ",string.byte(x)) end)
	    return str
	end

    -- hex2str(0x16)  eq  tostring(0x16)
    -- local h2b = {
    --     ["0"] = 0,
    --     ["1"] = 1,
    --     ["2"] = 2,
    --     ["3"] = 3,
    --     ["4"] = 4,
    --     ["5"] = 5,
    --     ["6"] = 6,
    --     ["7"] = 7,
    --     ["8"] = 8,
    --     ["9"] = 9,
    --     ["A"] = 10,
    --     ["B"] = 11,
    --     ["C"] = 12,
    --     ["D"] = 13,
    --     ["E"] = 14,
    --     ["F"] = 15
    -- }
	-- local function hex2str(hex)
	--     local s = string.gsub(hex, "(.)(.)%s", function ( h, l )
	--          return string.char(h2b[h]*16+h2b[l])
	--     end)
	--     return s
	-- end

    DUMP_1722 = false  -- default : not dump 1722
    local dumppath = "C:\\Users\\zhoubo\\Desktop"
    local filename1722 = dumppath .. "\\out.1722"
    local filename264 = dumppath .. "\\out.264"

    stream_infos_1722 = { } --global 1722 fileStream variable
    stream_info = { } --global h264 fileStream variable
    ieee1722 = { } --global 1722 protocol packet variable

    local filter_string_1722 = nil  -- not use
    local filter_string_h264 = nil  -- not use
    first_run = true   -- first run to calc sps,pps, second run to write to *.264
    local frameCount = 0 -- 1722 frame count

    -----------------------------------------------------------
    -----------------------------------------------------------
    -----------------------------------------------------------

    local function export_1722_to_file()
        tw1722 = TextWindow.new("Export IEEE1722 to File")
        twappend("Support Single NALU(1-23), STAP-A(24) and FU-A(28) format for H.264\n")

        local list_filter = ''
        if filter_string_1722 == nil or filter_string_1722 == '' then
            list_filter = "ieee1722"
        elseif string.find(filter_string_1722,"ieee1722")~=nil then
            list_filter = filter_string_1722
        else
            list_filter = "ieee1722 && "..filter_string_1722
        end
        twappend("Listener filter: " .. list_filter .. "\n")
        local my_1722_tap = Listener.new("frame", list_filter)


        -- running first time for counting and finding sps+pps, second time for real saving
        -- variable for storing rtp stream and dumping parameters
        local stream_infos = nil

        -- write a NALU or part of NALU to file.
        local function write_to_file(stream_info, str_bytes, begin_with_nalu_hdr, end_of_nalu)
            if first_run then
                stream_info.counter = stream_info.counter + 1

                if begin_with_nalu_hdr then
                    -- save SPS or PPS
                    local nalu_type = bit.band(str_bytes:byte(0,1), 0x1F)
                    if not stream_info.sps and nalu_type == 7 then
                        stream_info.sps = str_bytes
                        twappend("first_run set sps")
                    elseif not stream_info.pps and nalu_type == 8 then
                        stream_info.pps = str_bytes
                        twappend("first_run set pps")
                    end
                end

            else -- second time running

                if stream_info.counter2 == 0 then
                    -- write SPS and PPS to file header first
                    if stream_info.sps then
                        stream_info.file:write("\x00\x00\x00\x01")
                        stream_info.file:write(stream_info.sps)
                    else
                        twappend("Not found SPS for [" .. stream_info.filename .. "], it might not be played!")
                    end
                    if stream_info.pps then
                        stream_info.file:write("\x00\x00\x00\x01")
                        stream_info.file:write(stream_info.pps)
                    else
                        twappend("Not found PPS for [" .. stream_info.filename .. "], it might not be played!")
                    end
                end
            
                if begin_with_nalu_hdr then
                    -- *.264 raw file format seams that every nalu start with 0x00000001
                    stream_info.file:write("\x00\x00\x00\x01")
                end
                stream_info.file:write(str_bytes)
                stream_info.counter2 = stream_info.counter2 + 1

                -- update progress window's progress bar
                if stream_info.counter > 0 and stream_info.counter2 < stream_info.counter then
                    pgtw1722:update(stream_info.counter2 / stream_info.counter)
                end
            end
        end

        -- read RFC3984 about single nalu/stap-a/fu-a H264 payload format of rtp
        -- single NALU: one rtp payload contains only NALU
        local function process_single_nalu(stream_info, h264)
            write_to_file(stream_info, ieee1722:tvb():raw(28), true, true)
        end

        -- STAP-A: one rtp payload contains more than one NALUs
        local function process_stap_a(stream_info, h264)
            -- ########################################################################
            -- -- local h264tvb = h264:tvb()
            -- -- local offset = 1
            -- -- repeat
            -- --     local size = h264tvb(offset,2):uint()
            -- --     write_to_file(stream_info, h264tvb:raw(offset+2, size), true, true)
            -- --     offset = offset + 2 + size
            -- -- until offset >= h264tvb:len()
            -- ////////////////////////////////////////////////////////////////////////
            --local offset = 1
            --repeat
            --    -- ##### has no STAP-A pcap to test !!!!!!!!!!!!!!!
            --    local size = ieee1722:tvb():range(28 + offset, 2):uint()  -- size(Network Big Endian) maybe too big, ieee1722:tvb():raw() data out of bound
            --    twappend("STAP-A size : " ..tostring(size).. "")
            --    local strbuf = ieee1722:tvb():raw(28 + offset + 2, size)
            --    --twappend("strbuf : " ..tostring(strbuf).. "")
            --    write_to_file(stream_info, strbuf, true, true)
            --    offset = offset + 2 + size
            --until offset >= (ieee1722:tvb():len() - 28)
            -- ########################################################################

            local offset = 1		-- skip nal header of STAP-A
            repeat
                size = ieee1722:tvb():range(28 + offset, 2):uint() -- size(Network Big Endian) maybe too big, ieee1722:tvb():raw() data out of bound
                offset = offset + 2
                local next_nal_type = bit.band(ieee1722:get_index(28 + offset), 0x1F)
                twappend("STAP-A has naltype = "..next_nal_type..", size = "..size)
                --twappend("STAP-A:"..str2hex(ieee1722:tvb():raw(28 + offset, size)).."")
                write_to_file(stream_info, ieee1722:tvb():raw(28 + offset, size), true, true)
                offset = offset + size
            until offset >= (ieee1722:tvb():len() - 28)
        end

        -- FU-A: one rtp payload contains only one part of a NALU (might be begin, middle and end part of a NALU)
        local function process_fu_a(stream_info, h264)
            --local h264tvb = ieee1722:tvb():raw(28)
            local fu_idr = ieee1722:get_index(28)
            local fu_hdr = ieee1722:get_index(29)
            local end_of_nalu =  (bit.band(fu_hdr, 0x40) ~= 0)
            if bit.band(fu_hdr, 0x80) ~= 0 then
                -- start bit is set then save nalu header and body
                local nalu_hdr = bit.bor(bit.band(fu_idr, 0xE0), bit.band(fu_hdr, 0x1F))
                write_to_file(stream_info, string.char(nalu_hdr) .. ieee1722:tvb():raw(30), true, end_of_nalu)
            else
                -- start bit not set, just write part of nalu body
                write_to_file(stream_info, ieee1722:tvb():raw(30), false, end_of_nalu)
            end
        end

        -- call this function if a packet contains h264 payload
        function h264_packet()

            local h264 = ieee1722:tvb():raw(28)
            local hdr_type = bit.band(ieee1722:get_index(28), 0x1F)
            --twappend("1722 frame No : " .. frameCount .. ", h264_packet hdr_type : " ..tostring(hdr_type).. "")

			--PayloadType   PacketType         Packet Type Name                 Timestamp offset(in bits)   DON    Non-Interleaved    Interleaved
			-------------------------------------------------------------------------------------------------------------------------------------
			--0             reserved           -                                 -                          -      -                   -
			--1~23          Single NAL unit    Single NAL unit packet            0                          no     yes                 no
			--24            STAP-A             Single-time aggregation packet    0                          no     yes                 no
			--25            STAP-B             Single-time aggregation packet    0                          yes    no                  yes
			--26            MTAP16             Multi-time aggregation packet     16                         yes    no                  yes
			--27            MTAP24             Multi-time aggregation packet     24                         yes    no                  yes
			--28            FU-A               Fragmentation unit                0                          no     yes                 yes
			--29            FU-B               Fragmentation unit                0                          yes    no                  yes
			--30~31         reserved           -                                 -                          -      -                   -


            if hdr_type > 0 and hdr_type < 24 then
                -- Single NALU
                process_single_nalu(stream_info, h264)
            elseif hdr_type == 24 then
                -- STAP-A Single-time aggregation
                process_stap_a(stream_info, h264)
            elseif hdr_type == 28 then
                -- FU-A
                process_fu_a(stream_info, h264)
            else
                twappend("[Error] unknown type=" .. hdr_type .. " ; we only know 1-23(Single NALU),24(STAP-A),28(FU-A)!")
            end
        end

        -- call this function if a packet contains 1722 payload
        function my_1722_tap.packet(pinfo,tvb)
            if stream_infos_1722 == nil then
                -- not triggered by button event, so do nothing.
                return
            end
            local ieee1722s = { f_ieee1722() } -- using table because one packet may contains more than one RTP
            frameCount = frameCount + 1
            --twappend("1722 frame : " .. frameCount .. "")

            -- for all 1722 packet
            for i,ieee1722_f in ipairs(ieee1722s) do
                if ieee1722_f.len < 2 then
                    return
                end

                ieee1722 = ieee1722_f.range:bytes()
                local ieee1722_payload_subtype = ieee1722:get_index(0)  --"AVTP Subtype"
                local ieee1722_payload_svfield = bit.rshift(bit.band(ieee1722:get_index(1), 0x80), 7)  --"AVTP Stream ID Valid" : & 10000000b, right shift 7
                local ieee1722_payload_verfield = bit.rshift(bit.band(ieee1722:get_index(1), 0x70), 4)  --"AVTP Version" : & 01110000b, right shift 4
                -- twappend("ieee1722 subtype : " .. ieee1722_payload_subtype .."")
                -- twappend("ieee1722 svfield : " .. ieee1722_payload_svfield .."")
                -- twappend("ieee1722 verfield : " .. ieee1722_payload_verfield .."")

                -- ##### dump 1722's CVF:H.264 payload ####################################
                if DUMP_1722 then
                    if first_run then
                        stream_infos_1722.file:write("\x00\x00\x00\x01")
                        --local h264_payload = ieee1722:get_index(28) --avtp+cvf : 28 bytes
                        --right shift 28 to CVF:H.264 payload
                        stream_infos_1722.file:write(ieee1722:tvb():raw(28))
                    end
                end

               -- twappend("1722 tvb :" ..tostring(ieee1722:tvb():raw(28)).. "")
                h264_packet()
                --h264_packet(false, ieee1722:tvb():raw(28))
            end
        end


        local function export_1722()
            -- ##### dump 1722's CVF:H.264 payload ####################################
            if DUMP_1722 then
                twappend("export_1722 start")
                stream_infos_1722.filename = filename1722
                stream_infos_1722.file,msg = io.open(stream_infos_1722.filename, "wb")
                if msg then
                    twappend("io.open "..stream_infos_1722.filename..", error "..msg)
                end
            end

            stream_info.filename =  filename264
            stream_info.file,msg = io.open(stream_info.filename, "wb")
            if msg then
                twappend("io.open "..stream_info.filename..", error "..msg)
            end
            stream_info.counter = 0 -- counting h264 total NALUs
            stream_info.counter2 = 0 -- for second time running

            pgtw1722 = ProgDlg.new("Export 1722 to File Process", "Dumping 1722 data to file...")

            -- first time it runs for counting h.264 packets and finding SPS and PPS
            first_run = true
            frameCount = 0
            twappend("first_run start")
            retap_packets()

            -- second time it runs for saving h264 data to target file.
            first_run = false
            frameCount = 0
            twappend("\nsecond_run start")
            retap_packets()

            -- close progress window
            pgtw1722:close()

            -- ##### dump 1722's CVF:H.264 payload ####################################
            if DUMP_1722 then
                stream_infos_1722.file:flush()
                stream_infos_1722.file:close()
                stream_infos_1722.file = nil
            end

            stream_info.file:flush()
            stream_info.file:close()
            stream_info.file = nil

            twappend("\nieee1722 total frame : " .. frameCount .. "\n\n[".. stream_info.filename .. "] generated OK! \n")
            local function anony_fuc()
                twappend("ffplay -autoexit "..stream_info.filename)
                --copy_to_clipboard("ffplay -x 640 -y 640 -autoexit "..stream_info.filename)
                os.execute("ffplay -autoexit "..stream_info.filename)
            end
            tw1722:add_button("Play", function ()
                anony_fuc()
            end)

            tw1722:add_button("Browser", function () browser_open_data_file(dumppath) end)

        end

        tw1722:set_atclose(function ()
            my_1722_tap:remove()

            -- ##### dump 1722's CVF:H.264 payload ####################################
            if DUMP_1722 then
                local file1722 = io.open(stream_infos_1722.filename, "rb")
                if file1722 then file1722:close() end
                    os.remove (stream_infos_1722.filename)
            end

            local file264 = io.open(stream_info.filename, "rb")
            if file264 then file264:close() end
                os.remove (stream_info.filename)
        end)

        tw1722:add_button("1722 Export", function ()
            export_1722()
        end)

        -- tw1722:add_button("1722 Filter", function ()
        --     tw1722:close()
        --     dialog_menu()
        -- end)
    end

    local function dialog_func(str)
        filter_string_1722 = str
        export_1722_to_file()
    end

    function dialog_menu()
        new_dialog("Filter Dialog", dialog_func, "Filter")
    end

    local function dialog_default()
        export_1722_to_file()
    end

    -- Find this feature in menu "Tools"
    register_menu("Video/Export H264(1722)", dialog_default, MENU_TOOLS_UNSORTED)
end
