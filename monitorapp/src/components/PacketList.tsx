interface DataProp {
    basic_stats: any[];
    conversations: any[];
    data: any[];
    suspicious: any[];
    wireshark: any[];

}

interface PacketListProps {
    data: DataProp;
    onSelect: (pkt: any) => void;
  }
  
  export default function PacketList({ data, onSelect }: PacketListProps) {
    console.log(data);
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
          {data.wireshark.map((pkt:any) => (
            <tr
              key={pkt.no}
              className="hover:bg-gray-700 cursor-pointer"
              onClick={() => onSelect(pkt)}
            >
              <td className="px-2 py-1">{pkt.no}</td>
              <td className="px-2 py-1">{pkt.timestamp.toFixed(6)}</td>
              <td className="px-2 py-1">{pkt.packet?.ip?.src_ip || "-"}</td>
              <td className="px-2 py-1">{pkt.packet?.ip?.dst_ip || "-"}</td>
              <td className="px-2 py-1">{pkt?.protocol || "-"}</td>
              <td className="px-2 py-1">{pkt.length}</td>
              <td className="px-2 py-1">{pkt.info}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  