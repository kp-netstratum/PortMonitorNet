interface PacketBytesProps {
    raw: { hex_formatted: string; ascii: string };
  }
  
  export default function PacketBytes({ raw }: PacketBytesProps) {
    return (
      <div className="p-3 text-xs font-mono">
        <h2 className="font-bold text-xl mb-2">Raw Bytes</h2>
        <div className="flex flex-col gap-2">
          <h2 className="font-bold mb-2">Hex</h2>
          <div className="bg-gray-800 p-2 rounded flex flex-wrap h-auto whitespace-pre-line w-full overflow-auto"><p>{raw.hex_formatted}</p></div>
          <h2 className="font-bold my-2">ASCII</h2>
          <div className="bg-gray-800 p-2 rounded flex flex-wrap h-auto">{raw.ascii}</div>
        </div>
      </div>
    );
  }
  