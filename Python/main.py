from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette import status
import os
import tempfile
from fastapi.responses import JSONResponse

from src.converterV2 import pysharkAnalysis

app = FastAPI()

# Enable CORS for frontend origin (default Vite dev server). Override via FRONTEND_ORIGIN env var.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_pcap(file: UploadFile = File(...)):
    # Validate file extension
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided",
        )
    
    filename = os.path.basename(file.filename)
    if not filename.lower().endswith(".pcap"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .pcap files are allowed",
        )

    # Read file content
    try:
        data = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read file: {str(e)}",
        )

    if not data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    # Create temporary file for analysis
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as temp_file:
            temp_file.write(data)
            temp_path = temp_file.name

        # Analyze the file
        analysis_result = await pysharkAnalysis(temp_path)
        
        return JSONResponse(content={
            "filename": file.filename,
            "file_size": len(data),
            "analysis": analysis_result
        })
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"Analysis failed: {str(e)}"
        )
    
    finally:
        # Clean up temporary file
        try:
            if 'temp_path' in locals():
                os.unlink(temp_path)
        except Exception:
            pass  # Ignore cleanup errors