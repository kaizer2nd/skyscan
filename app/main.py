from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.database.mongodb import connect_to_mongo, close_mongo_connection
from app.auth.auth_router import router as auth_router
from app.users.users_router import router as users_router
from app.scan.scan_router import router as scan_router
from app.config import settings
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Advanced Vulnerability Detection and Assessment Platform"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(scan_router)

# Mount static files
frontend_path = Path(__file__).parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path / "static")), name="static")


# Event handlers
@app.on_event("startup")
async def startup_event():
    """Connect to MongoDB on startup"""
    logger.info(f"Starting {settings.APP_NAME} v{settings.VERSION}")
    await connect_to_mongo()
    logger.info("Application startup complete")


@app.on_event("shutdown")
async def shutdown_event():
    """Close MongoDB connection on shutdown"""
    logger.info("Shutting down application")
    await close_mongo_connection()
    logger.info("Application shutdown complete")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint - serve index.html"""
    index_file = frontend_path / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.VERSION,
        "docs": "/docs"
    }


# Health check
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.VERSION
    }


# Serve frontend pages
@app.get("/login")
async def login_page():
    """Serve login page"""
    login_file = frontend_path / "login.html"
    if login_file.exists():
        return FileResponse(str(login_file))
    return {"message": "Login page not found"}


@app.get("/register")
async def register_page():
    """Serve registration page"""
    register_file = frontend_path / "register.html"
    if register_file.exists():
        return FileResponse(str(register_file))
    return {"message": "Register page not found"}


@app.get("/dashboard")
async def dashboard_page():
    """Serve dashboard page"""
    dashboard_file = frontend_path / "dashboard.html"
    if dashboard_file.exists():
        return FileResponse(str(dashboard_file))
    return {"message": "Dashboard page not found"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
