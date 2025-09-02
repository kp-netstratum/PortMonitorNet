import { useEffect, useState } from "react";
import PacketList from "./PacketList";
import PacketDetails from "./PacketDetails";
import PacketBytes from "./PacketBytes";
import api from "../../api/api";

type UploadResponse = {
  filename: string;
  file_size: number;
  analysis: any;
};

export default function WiresharkMain({ data, fileData, setFileData }: any) {
  const [packets, setPackets] = useState<any>(data.analysis);
  const [selectedPacket, setSelectedPacket] = useState<any>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState<number>(20);

  const fetchPackets = async (
    page: number = 1,
    pageSize: number = 20,
    data: any
  ) => {
    // `http://localhost:8000/upload?page=${page}&page_size=${pageSize}`
    const res = await api.post<UploadResponse>(
      `/upload?page=${page}&page_size=${pageSize}`,
      data,
      {
        // baseUrl defaults to VITE_API_BASE_URL in the api helper
        headers: {}, // do not set Content-Type for FormData
      }
    );
    return res;
  };

  const decrementPage = async () => {
    if (currentPage > 1) {
      const nextPage = currentPage - 1;
      setCurrentPage(nextPage);
      const formData = new FormData();
      formData.append("file", fileData);
      const dat = await fetchPackets(nextPage, pageSize, formData);
      setPackets(dat.analysis);
    }
  };

  const incrementPage = async () => {
    if (currentPage < data.pagination.total_pages) {
      const nextPage = currentPage + 1;
      setCurrentPage(nextPage);
      const formData = new FormData();
      formData.append("file", fileData);
      const dat = await fetchPackets(nextPage, pageSize, formData);
      setPackets(dat.analysis);
    }
  };

  const pageSizeChange = async(size:number) => {
    setPageSize(size);
    const formData = new FormData();
    formData.append("file", fileData);
    const dat = await fetchPackets(currentPage, size, formData);
    setPackets(dat.analysis);
  }

  useEffect(() => {
    console.log(packets);
    const paginationData = data.pagination;
    setCurrentPage(paginationData.page);
  }, []);

  return (
    <div className="h-screen flex flex-col bg-gray-900 text-gray-100 w-screen p-5">
      {/* Packet List */}
      <div className="flex flex-col overflow-auto border-b-2 border-gray-700 h-[50%]">
        <PacketList
          data={packets}
          select={selectedPacket}
          onSelect={setSelectedPacket}
        />
      </div>
      <div className="flex flex-row gap-5 py-5 text-sm">
        <div
          className="p-2 bg-gray-700 rounded-md cursor-pointer hover:bg-blue-600"
          onClick={() => {
            decrementPage();
          }}
        >
          Previous
        </div>
        <div
          className="p-2 bg-gray-700 rounded-md cursor-pointer hover:bg-blue-600"
          onClick={() => {
            incrementPage();
          }}
        >
          Next
        </div>
        <select
          className="text-black bg-white px-3 rounded-md"
          value={pageSize}
          defaultValue={pageSize}
          onChange={(e: React.ChangeEvent<HTMLSelectElement>) => pageSizeChange(Number(e.target.value))}
        >
          <option value={10}>10</option>
          <option value={20}>20</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>
      </div>
      <div className="flex flex-row w-full max-h-[40%]">
        {/* Packet Details */}
        <div className=" flex-1 border-gray-700 w-1/2">
          {selectedPacket ? (
            <PacketDetails packet={selectedPacket} />
          ) : (
            <p className="p-4 text-gray-400">Select a packet to view details</p>
          )}
        </div>

        {/* Packet Bytes */}
        <div className="overflow-auto flex-1 w-1/2">
          {selectedPacket ? (
            <PacketBytes raw={selectedPacket.raw_data} />
          ) : (
            <p className="p-4 text-gray-400">Select a packet to view bytes</p>
          )}
        </div>
      </div>
    </div>
  );
}
