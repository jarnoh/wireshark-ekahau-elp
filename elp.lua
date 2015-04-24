--
-- Simple Wireshark dissector for Ekahau Location Protocol (ELP).
--
-- I couldn't find any protocol documentation, so I reverse engineered it.
-- 
-- Each Ekahau tag sends periodic updates to Ekahau Positioning engine in UDP port 8552.  
-- Each datagram contains 16 bytes of header, 16 byte tag info and several 16 byte 
-- entries for each scanned AP.  Engine responds to same port, but I have not yet 
-- examined the response packets
-- 
-- jarnoh@komplex.org (April 2015)
--

ELP_proto = Proto("ELP","Ekahau Location Protocol")

ElpScanReason={
	"button1", "motion start", "periodic", 
	"calibrate", "after motion", "button2", "tamper alarm",
	"button3", "charger status", "safety switch", "low battery",
	"motion stagnant", "menu selection", "supplementary", "location beacon",
	"", "", "","", -- not specified
	"network"
}


function elp_reason(x)
  return ElpScanReason[x%256] .. string.format(" (%x)", x)
end

-- create a function to dissect it
function ELP_proto.dissector(buffer,pinfo,tree)
	pinfo.cols.protocol = "ELP"

	local subtree = tree:add(ELP_proto,buffer(),"ELP Protocol Data")

	hdr = subtree:add(buffer(2,2),"Header")
	hdr:add(buffer(0,4),"Magic bytes: " .. buffer(0,4):string())
	--hdr:add(buffer(4,2),"Protocol version: " .. buffer(4,2):uint() .. "." .. buffer(4,2):uint() )
	--hdr:add(buffer(8,2),"?? zero " .. tostring(buffer(8,2)))
	--hdr:add(buffer(10,2),"?? zero " .. tostring(buffer(10,2)))
	--hdr:add(buffer(12,2),"?? " .. tostring(buffer(12,2)))

	local len=buffer(14,2):uint()
	hdr:add(buffer(14,2),"Payload length: " .. len)

	if len>=16 then
		tag = subtree:add(buffer(16,16),"Tag information")
		tag:add(buffer(16,6), "HW addr: " .. tostring(buffer(16,6)) )
		-- tag:add(buffer(22,2), "?? " .. tostring(buffer(22,2)) )
		tag:add(buffer(24,2), "Battery: " .. buffer(24,2):uint() )
		-- tag:add(buffer(26,2), "?? " .. tostring(buffer(26,2)) )
		tag:add(buffer(28,2), "Reason: " .. elp_reason(buffer(28,2):uint()) )
		tag:add(buffer(30,2), "Scan mask: " .. tostring(buffer(30,2)) )
		else
		tag = subtree:add(buffer(16,len),"Engine response")
		-- TODO figure out buzzer etc
		tag:add(buffer(16,len), "Bytes " .. tostring(buffer(16,len)) )
	end

	if len>=32 then
		mac = subtree:add(buffer(32,len-32),"Scan information, " .. len/16-1 .. " APs:")
		for off=32,len,16 do
		  local rssi=-65536+buffer(off+6,2):uint() -- TODO how to do signed int?
		  local ch = buffer(off+8,2):uint()
		  mac:add(buffer(off,6), string.format("%s, ch: %d, rssi: %d dB", tostring(buffer(off,6)), ch, rssi))

		  -- mac:add(buffer(off+10,6), "?? " .. tostring(buffer(off+10,6)))
		end
	end

end

udp_table = DissectorTable.get("udp.port")
udp_table:add(8552,ELP_proto)

