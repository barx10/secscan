
import asyncio
import logging
from packages.core.pipeline import ScanPipeline
from packages.core.models import ScanConfig

logging.basicConfig(level=logging.INFO)

async def main():
    print("Starting debug scan...")
    pipeline = ScanPipeline()
    
    def progress(msg, p):
        print(f"PROGRESS: {p*100}% - {msg}")
        
    pipeline.set_progress_callback(progress)
    
    url = "https://github.com/barx10/ki_forordninga"
    config = ScanConfig(scan_types=["secrets", "sast"])
    
    try:
        print(f"Scanning {url}...")
        result = await pipeline.scan_git_url(url, config)
        print("Scan finished!")
        print(f"Status: {result.scan.status}")
        print(f"Findings: {len(result.findings)}")
        if result.scan.error_message:
            print(f"Error: {result.scan.error_message}")
            
        if hasattr(result, "adapter_status"):
             print("Adapter Status:")
             for name, status in result.adapter_status.items():
                 print(f" - {name}: Success={status['success']}, Msg={status['message']}")
                 
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")

if __name__ == "__main__":
    asyncio.run(main())
