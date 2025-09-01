import { useState } from "react";
import PacketList from "./PacketList";
import PacketDetails from "./PacketDetails";
import PacketBytes from "./PacketBytes";

export default function WiresharkMain({ data }: any) {
  const [packets, setPackets] = useState<any>(data);
  const [selectedPacket, setSelectedPacket] = useState<any>(null);

  return (
    <div className="h-screen flex flex-col bg-gray-900 text-gray-100">
      {/* Packet List */}
      <div className="flex overflow-auto border-b border-gray-700">
        <PacketList data={packets} onSelect={setSelectedPacket} />
      </div>
      <div className="flex flex-row w-screen max-h-[40%]">
        {/* Packet Details */}
        <div className=" flex-1 overflow-auto border-b border-gray-700 w-1/2">
          {selectedPacket ? (
            <PacketDetails packet={selectedPacket} />
          ) : (
            <p className="p-4 text-gray-400">Select a packet to view details</p>
          )}
        </div>

        {/* Packet Bytes */}
        <div className="w-1/2 overflow-auto flex-1 flex">
          {selectedPacket ? (
            <PacketBytes raw={selectedPacket.raw} />
          ) : (
            <p className="p-4 text-gray-400">Select a packet to view bytes</p>
          )}
        </div>
      </div>
    </div>
  );
}
