-- ************************* MRVL RMU ***************************
-- Wireshark RMU dissector
-- Version: v0.11.0000
--
-- Usage:
--
-- 1. Load dissector via command line
--    wireshark -Xlua_script:updrmu2.lua
--    or
--    wireshark -Xlua_script:updrmu2.lua example.pcap
--
-- 2. Copy updrmu2.lua to a Wireshark Lua Plugins directory
--    for auto-load at Wireskark startup.
--    See "Help --> About Wireshark --> Folders" for folder
--    locations.
--

-- declare our protocol (UDP = User Datagram Protocol)
local p_udprmu = Proto.new("UDPRMU", "UDP RMU Protocol")
local p_ermu = Proto.new("eRMU", "eRMU Protocol")
local p_rmu = Proto.new("RMU", "RMU Protocol")
