interface PacketDetailsProps {
    packet: any;
  }
  
  export default function PacketDetails({ packet }: PacketDetailsProps) {
    return (
      <div className="p-3 h-full w-full">
        <h2 className="font-bold text-lg mb-2">Packet #{packet.no}</h2>
        <pre className="bg-gray-800 p-2 pb-10 rounded text-xs h-full overflow-y-auto">
          {JSON.stringify(packet, null, 2)}
        </pre>
      </div>
    );
  }
  