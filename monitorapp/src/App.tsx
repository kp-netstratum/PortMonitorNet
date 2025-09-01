import { BrowserRouter, Route, Routes } from 'react-router-dom'
import './App.css'
import Dashboard from './components/Dashboard'
import Analysis from './components/Analysis';
import { useState } from 'react';
import Table from './components/Table';
import WiresharkMain from './components/WiresharkMain';


function App() {
  type UploadResponse = {
    filename: string
    file_size: number
    analysis: unknown
  }

  const [uploadResult, setUploadResult] = useState<UploadResponse | null>(null)

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path='/'
          element={<Dashboard onUploaded={(res) => setUploadResult(res)} />}
        />
        <Route
          path='/analysis'
          element={<Analysis data={uploadResult?.analysis ?? null} />}
        />
        <Route
          path='/table'
          element={<Table data={uploadResult?.analysis ?? null} />}
        />
        <Route
          path='/wireshark'
          element={<WiresharkMain data={uploadResult?.analysis ?? null} />}
        />
      </Routes>
    </BrowserRouter>
  )
}

export default App
