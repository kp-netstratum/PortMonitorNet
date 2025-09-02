interface DataProp {
    basic_stats: any[];
    conversations: any[];
    data: any[];
    suspicious: any[];
    wireshark: any[];

}

interface PacketListProps {
    data: any;
    select: string;
    onSelect: (pkt: any) => void;
  }
  
  export default function PacketList({ data, onSelect, select }: PacketListProps) {

    console.log(data, 'data inside packetList component')
    return (
      <table className="w-full text-sm">
        <thead className="bg-gray-800 text-gray-300 sticky top-0">
          <tr>
            <th className="px-2 py-1 text-left">No.</th>
            <th className="px-2 py-1 text-left">Time</th>
            <th className="px-2 py-1 text-left">Source</th>
            <th className="px-2 py-1 text-left">Destination</th>
            <th className="px-2 py-1 text-left">Protocol</th>
            <th className="px-2 py-1 text-left">Length</th>
            <th className="px-2 py-1 text-left">Info</th>
          </tr>
        </thead>
        <tbody>
          {data.map((pkt:any) => (
            <tr
              key={pkt.no}
              className={`hover:bg-gray-700 cursor-pointer ${select === pkt && 'bg-gray-700'}`}
              onClick={() => onSelect(pkt)}
            >
              <td className="px-2 py-1">{pkt.frame_info.frame_number}</td>
              <td className="px-2 py-1">{pkt.timing.absolute_time}</td>
              <td className="px-2 py-1">{pkt.frame_info.src || "-"}</td>
              <td className="px-2 py-1">{pkt.frame_info.dst || "-"}</td>
              <td className="px-2 py-1">{pkt?.frame_info.protocols_in_frame || "-"}</td>
              <td className="px-2 py-1">{pkt.frame_info.capture_length_bytes}</td>
              <td className="px-2 py-1">{pkt.frame_info.info}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  