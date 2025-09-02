# from fastapi import FastAPI, UploadFile, File, HTTPException, Query
# from fastapi.middleware.cors import CORSMiddleware
# from starlette import status
# import os
# import tempfile
# from fastapi.responses import JSONResponse

# from src.converterV2 import pysharkAnalysis
# from src.converterV3 import analyze_pcap_to_json
# # from src.wireshark import wireshark_analysis

# app = FastAPI()

# # Enable CORS for frontend origin (default Vite dev server). Override via FRONTEND_ORIGIN env var.
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# @app.get("/")
# def read_root():
#     return {"Hello": "World"}


# @app.post("/upload", status_code=status.HTTP_201_CREATED)
# async def upload_pcap(
#     file: UploadFile = File(...),
#     page: int = Query(1, ge=1),  # default = 1
#     page_size: int = Query(50, ge=1, le=200),  # default = 50, max 200
# ):
#     # Validate file extension
#     if not file.filename:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="No filename provided",
#         )

#     filename = os.path.basename(file.filename)
#     if not filename.lower().endswith(".pcap"):
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Only .pcap files are allowed",
#         )

#     try:
#         data = await file.read()
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail=f"Failed to read file: {str(e)}",
#         )

#     if not data:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Uploaded file is empty",
#         )

#     try:
#         with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as temp_file:
#             temp_file.write(data)
#             temp_path = temp_file.name

#         # Analyze packets
#         # all_results = await pysharkAnalysis(temp_path)
#         all_results = await analyze_pcap_to_json(temp_path)
        
#         # Pagination
#         total_items = len(all_results)
#         total_pages = (total_items + page_size - 1) // page_size
#         start = (page - 1) * page_size
#         end = start + page_size
#         paginated_results = all_results[start:end]

#         return JSONResponse(
#             content={
#                 "filename": file.filename,
#                 "file_size": len(data),
#                 "pagination": {
#                     "page": page,
#                     "page_size": page_size,
#                     "total_items": total_items,
#                     "total_pages": total_pages,
#                 },
#                 "analysis": paginated_results,
#             }
#         )

#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Analysis failed: {str(e)}",
#         )

#     finally:
#         try:
#             if "temp_path" in locals():
#                 os.unlink(temp_path)
#         except Exception:
#             pass



# from fastapi import FastAPI, UploadFile, File, HTTPException, Query
# from fastapi.middleware.cors import CORSMiddleware
# from starlette import status
# import os
# import tempfile
# from fastapi.responses import JSONResponse

# # from src.converterV2 import pysharkAnalysis
# from src.converterV3 import analyze_pcap_to_json
# # from src.wireshark import wireshark_analysis

# app = FastAPI()

# # Enable CORS for frontend origin (default Vite dev server). Override via FRONTEND_ORIGIN env var.
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# @app.get("/")
# def read_root():
#     return {"Hello": "World"}


# @app.post("/upload", status_code=status.HTTP_201_CREATED)
# async def upload_pcap(
#     file: UploadFile = File(...),
#     page: int = Query(1, ge=1),  # default = 1
#     page_size: int = Query(50, ge=1, le=200),  # default = 50, max 200
# ):
#     # Validate file extension
#     if not file.filename:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="No filename provided",
#         )

#     filename = os.path.basename(file.filename)
#     if not filename.lower().endswith(".pcap"):
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Only .pcap files are allowed",
#         )

#     try:
#         data = await file.read()
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail=f"Failed to read file: {str(e)}",
#         )

#     if not data:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Uploaded file is empty",
#         )

#     try:
#         with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as temp_file:
#             temp_file.write(data)
#             temp_path = temp_file.name

#         # Analyze packets - this returns a dictionary with analysis data
#         analysis_data = analyze_pcap_to_json(temp_path)
        
#         if not analysis_data:
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail="Failed to analyze PCAP file"
#             )
        
#         # Extract the frames list for pagination
#         all_frames = analysis_data
        
#         # Pagination on frames
#         total_items = len(all_frames)
#         total_pages = (total_items + page_size - 1) // page_size if total_items > 0 else 1
#         start = (page - 1) * page_size
#         end = start + page_size
#         paginated_frames = all_frames[start:end]

#         # Prepare response with paginated frames and metadata
#         response_data = {
#             "filename": file.filename,
#             "file_size": len(data),
#             "pagination": {
#                 "page": page,
#                 "page_size": page_size,
#                 "total_items": total_items,
#                 "total_pages": total_pages,
#             },
#             # Include metadata from the analysis
#             "pcap_info": analysis_data.get('pcap_info', {}),
#             "statistics": analysis_data.get('statistics', {}),
#             "tcp_streams": analysis_data.get('tcp_streams', []),
#             # Paginated frames
#             "frames": paginated_frames,
#         }

#         return JSONResponse(content=response_data)

#     except Exception as e:
#         # More detailed error reporting for debugging
#         import traceback
#         error_detail = f"Analysis failed: {str(e)}"
#         print(f"Error details: {error_detail}")
#         print(f"Traceback: {traceback.format_exc()}")
        
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=error_detail,
#         )

#     finally:
#         try:
#             if "temp_path" in locals():
#                 os.unlink(temp_path)
#         except Exception:
#             pass


from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from starlette import status
import os
import tempfile
from fastapi.responses import JSONResponse

from src.converterV2 import pysharkAnalysis
from src.converterV3 import analyze_pcap_to_json
from src.converterV4 import analyze_pcap_async
# from src.wireshark import wireshark_analysis

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
async def upload_pcap(
    file: UploadFile = File(...),
    page: int = Query(1, ge=1),  # default = 1
    page_size: int = Query(50, ge=1, le=200),  # default = 50, max 200
):
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

    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as temp_file:
            temp_file.write(data)
            temp_path = temp_file.name

        # Analyze packets - this returns a list of packets (matching old format)
        all_packets = await analyze_pcap_async(temp_path)
        # print(all_packets)
        if not all_packets:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to analyze PCAP file"
            )
        
        frames = all_packets['frames']
        # Pagination on packets
        total_items = len(frames)
        total_pages = (total_items + page_size - 1) // page_size if total_items > 0 else 1
        start = (page - 1) * page_size
        end = start + page_size
        paginated_packets = frames[start:end]

        # Prepare response with paginated packets
        response_data = {
            "filename": file.filename,
            "file_size": len(data),
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": total_items,
                "total_pages": total_pages,
            },
            # Return the paginated packet list
            "analysis": paginated_packets,
            "pcap_info": all_packets['pcap_info']
        }

        return JSONResponse(content=response_data)

    except Exception as e:
        # More detailed error reporting for debugging
        import traceback
        error_detail = f"Analysis failed: {str(e)}"
        print(f"Error details: {error_detail}")
        print(f"Traceback: {traceback.format_exc()}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_detail,
        )

    finally:
        try:
            if "temp_path" in locals():
                os.unlink(temp_path)
        except Exception:
            pass