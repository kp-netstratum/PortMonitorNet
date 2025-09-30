# Wireshark PCAP Analyzer API

A FastAPI-based web service for analyzing PCAP (packet capture) files using PyShark and Scapy libraries. This application provides comprehensive network packet analysis with detailed frame-by-frame information, statistics, and security analysis.

## Features

- **PCAP File Upload**: Upload .pcap files via HTTP POST
- **Comprehensive Analysis**: Extract detailed packet information including:
  - Ethernet layer details (MAC addresses, OUI, frame types)
  - IP layer analysis (headers, flags, DSCP, ECN)
  - TCP/UDP layer information (ports, flags, sequences)
  - Application layer data (HTTP, DNS, etc.)
- **Network Statistics**: Generate traffic statistics and conversation analysis
- **Paginated Results**: Handle large PCAP files with pagination support
- **Multiple Analysis Engines**: Choose from different converter implementations
- **CORS Support**: Ready for frontend integration

## Prerequisites

Before running this application, ensure you have:

1. **Python 3.8+** installed
2. **Wireshark/TShark** installed (required for PyShark)
   - Download from: https://www.wireshark.org/download.html
   - Ensure `tshark` is in your system PATH

## Installation

1. **Clone or navigate to the project directory**:
   ```bash
   cd C:\Users\Krishnaprasad\Netstratum\R&D\Wireshark\Python
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

The application uses the following default settings:

- **Port**: 8000 (FastAPI default)
- **CORS Origins**: `http://localhost:5173` (Vite dev server)
  - Override with environment variable: `FRONTEND_ORIGIN`
- **Pagination**: Default 50 items per page, max 200

## Usage

### Starting the Application

Run the FastAPI server using uvicorn:

```bash
uvicorn main:app --reload
```

The API will be available at:
- **Main API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

### API Endpoints

#### 1. Health Check
```
GET /
```
Returns a simple "Hello World" response to verify the API is running.

#### 2. PCAP Analysis
```
POST /upload
```

**Parameters**:
- `file` (required): PCAP file to analyze
- `page` (optional): Page number for pagination (default: 1)
- `page_size` (optional): Items per page (default: 50, max: 200)

**Example using curl**:
```bash
curl -X POST "http://localhost:8000/upload?page=1&page_size=50" \
     -H "accept: application/json" \
     -H "Content-Type: multipart/form-data" \
     -F "file=@your_capture.pcap"
```

**Response Format**:
```json
{
  "filename": "your_capture.pcap",
  "file_size": 12345,
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total_items": 150,
    "total_pages": 3
  },
  "analysis": [
    {
      "frame_number": 1,
      "timestamp": "2023-01-01T12:00:00",
      "length": 64,
      "protocols": ["Ethernet", "IP", "TCP"],
      "source_ip": "192.168.1.1",
      "destination_ip": "192.168.1.2",
      // ... detailed packet information
    }
  ],
  "pcap_info": {
    "filename": "your_capture.pcap",
    "total_packets": 150,
    "analysis_timestamp": "2023-01-01T12:00:00"
  }
}
```

## Analysis Modules

The application includes multiple analysis implementations:

1. **converter.py**: Basic PyShark-based analyzer with statistics
2. **converterV2.py**: Enhanced analyzer with conversation tracking
3. **converterV3.py**: Comprehensive frame-by-frame analysis
4. **converterV4.py**: Complete analyzer with security analysis (currently active)
5. **wireshark.py**: Scapy-based analyzer with raw packet data

## Development

### Project Structure
```
Python/
├── main.py                 # FastAPI application entry point
├── src/
│   ├── converter.py        # Basic PCAP analyzer
│   ├── converterV2.py      # Enhanced analyzer
│   ├── converterV3.py      # Frame analyzer
│   ├── converterV4.py      # Complete analyzer (active)
│   └── wireshark.py        # Scapy-based analyzer
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

### Running Tests
```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests (if test files exist)
pytest
```

### Environment Variables

- `FRONTEND_ORIGIN`: Override CORS origin (default: `http://localhost:5173`)

## Troubleshooting

### Common Issues

1. **TShark not found**: Ensure Wireshark is installed and `tshark` is in PATH
2. **Permission errors**: Run with appropriate permissions for file access
3. **Memory issues**: Use pagination for large PCAP files
4. **CORS errors**: Check frontend origin configuration

### Supported File Formats

- `.pcap` files (libpcap format)
- `.pcapng` files (may require conversion)

## Dependencies

### Core Libraries
- **FastAPI**: Modern web framework for building APIs
- **PyShark**: Python wrapper for TShark (Wireshark)
- **Scapy**: Powerful packet manipulation library
- **Uvicorn**: ASGI server implementation

### Analysis Capabilities
- Ethernet frame analysis
- IP packet dissection
- TCP/UDP transport analysis
- Application layer protocol detection
- Network conversation tracking
- Traffic statistics generation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is for research and development purposes within Netstratum.

## Support

For issues or questions, contact the development team or create an issue in the project repository.
