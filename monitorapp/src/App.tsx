import { BrowserRouter, Route, Routes } from "react-router-dom";
import "./App.css";
import Dashboard from "./components/Dashboard";
import Analysis from "./components/Analysis";
import { useState } from "react";
import Table from "./components/Table";
import WiresharkMain from "./components/WiresharkMain";

function App() {
  type UploadResponse = {
    filename: string;
    file_size: number;
    analysis: unknown;
  };


  const [uploadResult, setUploadResult] = useState<UploadResponse | null>(null);
  const [fileData, setFileData] = useState<any>(null);

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/"
          element={
            <Dashboard
              onUploaded={(res) => setUploadResult(res)}
              fileData={fileData}
              setFileData={setFileData}
            />
          }
        />
        <Route
          path="/analysis"
          element={<Analysis data={uploadResult?.analysis ?? null} />}
        />
        <Route
          path="/table"
          element={<Table data={uploadResult?.analysis ?? null} />}
        />
        <Route
          path="/wireshark"
          element={
            <WiresharkMain
              data={uploadResult ?? null}
              fileData={fileData}
              setFileData={setFileData}
            />
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
