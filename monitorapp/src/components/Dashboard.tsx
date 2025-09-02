import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../../api/api";

type UploadResponse = {
  filename: string;
  file_size: number;
  analysis: unknown;
};

interface DashboardProps {
  onUploaded: (result: UploadResponse) => void;
  fileData: any; // replace `any` with the actual file type if you know it
  setFileData: React.Dispatch<React.SetStateAction<any>>;
}

function Dashboard({ onUploaded, fileData, setFileData }: DashboardProps) {
  const [file, setFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<UploadResponse | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const navigate = useNavigate();

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
    setResult(res);
    onUploaded(res);
  };

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setResult(null);
    if (!file) return;
    setFileData(file)
    try {
      setIsUploading(true);
      const formData = new FormData();
      formData.append("file", file);
      await fetchPackets(1, 20, formData);
      navigate("/wireshark");
    } catch (err) {
      const message = err instanceof Error ? err.message : "Upload failed";
      setError(message);
    } finally {
      setIsUploading(false);
    }
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = e.target.files?.[0] ?? null;
    setFile(selected);
  }

  function handleDragOver(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragging) setIsDragging(true);
  }

  function handleDragLeave(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const droppedFile = e.dataTransfer.files?.[0] ?? null;
    if (droppedFile) setFile(droppedFile);
  }

  function handleBrowseClick() {
    inputRef.current?.click();
  }

  console.log(result, "qwerty");

  // const containerStyle: React.CSSProperties = {
  //   maxWidth: 760,
  //   margin: "40px auto",
  //   padding: 24,
  //   borderRadius: 12,
  //   border: "1px solid #e5e7eb",
  //   boxShadow: "0 2px 10px rgba(0,0,0,0.05)",
  //   background: "#fff",
  // };

  // const titleStyle: React.CSSProperties = {
  //   margin: 0,
  //   marginBottom: 16,
  //   fontSize: 22,
  //   fontWeight: 700,
  //   color: "#111827",
  // };

  // const subtitleStyle: React.CSSProperties = {
  //   margin: 0,
  //   marginBottom: 20,
  //   color: "#6b7280",
  // };

  const dropzoneStyle: React.CSSProperties = {
    position: "relative",
    background: isDragging ? "bfefff" : "#f9fafb",
    color: "#374151",
    borderRadius: 12,
    padding: 28,
    textAlign: "center" as const,
    transition: "all 0.15s ease-in-out",
    cursor: "pointer",
  };

  const helperTextStyle: React.CSSProperties = {
    marginTop: 8,
    fontSize: 12,
    color: "#6b7280",
  };

  const buttonStyle: React.CSSProperties = {
    marginTop: 16,
    padding: "10px 16px",
    background: file ? "#2563eb" : "#344256",
    color: "#fff",
    border: 0,
    borderRadius: 8,
    fontWeight: 600,
    cursor: isUploading ? "not-allowed" : "pointer",
  };

  const metaStyle: React.CSSProperties = {
    marginTop: 16,
    padding: 12,
    background: "#f3f4f6",
    borderRadius: 8,
    fontSize: 14,
  };

  return (
    <div className="h-[100vh] bg-gray-900 flex flex-col justify-center items-center">
      <div className="bg-gray-800 w-[60%] p-12 rounded-xl border-gray-700 border">
        <h2 className="text-2xl font-bold text-white">Upload PCAP</h2>
        <p className="text-xl text-white mb-5">
          Drag and drop a file below, or click to browse.
        </p>
        <form onSubmit={handleSubmit}>
          <input
            ref={inputRef}
            type="file"
            onChange={handleFileChange}
            style={{ display: "none" }}
          />
          <div
            onClick={handleBrowseClick}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            style={dropzoneStyle}
          >
            <div>
              {file ? (
                <>
                  <div style={{ fontWeight: 600 }}>{file.name}</div>
                  <div style={helperTextStyle}>Ready to upload</div>
                </>
              ) : (
                <>
                  <div style={{ fontWeight: 600 }}>Drop your file here</div>
                  <div style={helperTextStyle}>or click to browse</div>
                </>
              )}
            </div>
          </div>

          <button
            type="submit"
            disabled={!file || isUploading}
            style={buttonStyle}
          >
            {isUploading ? "Uploading..." : "Upload & Analyze"}
          </button>
        </form>

        {error && <p style={{ color: "#b91c1c", marginTop: 12 }}>{error}</p>}

        {result && (
          <div style={metaStyle}>
            <div>
              <strong>Uploaded:</strong> {result.filename}
            </div>
            <div>
              <strong>Size:</strong> {result.file_size} bytes
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Dashboard;
