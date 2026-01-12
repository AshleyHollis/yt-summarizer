"""One-time script to refresh existing video metadata from YouTube via API."""

import asyncio
import httpx


async def main():
    """Refresh all videos with proper metadata from YouTube via API."""
    api_base = "http://localhost:8000"

    async with httpx.AsyncClient(timeout=120.0) as client:
        # Get all videos
        response = await client.get(f"{api_base}/api/v1/library/videos?page_size=50")
        response.raise_for_status()
        data = response.json()
        videos = data["videos"]

        print(f"Found {len(videos)} videos to refresh")

        for video in videos:
            video_id = video["video_id"]
            youtube_video_id = video["youtube_video_id"]
            print(f"\nRefreshing video: {youtube_video_id} ({video_id})")
            print(f"  Current title: {video['title']}")
            print(f"  Current channel: {video['channel_name']}")

            try:
                # Call the refresh-metadata endpoint
                response = await client.post(f"{api_base}/api/v1/videos/{video_id}/refresh-metadata")
                response.raise_for_status()
                updated = response.json()

                print(f"  -> Updated title: {updated['title']}")
                print(f"  -> Updated channel: {updated['channel_name']}")

            except httpx.HTTPStatusError as e:
                print(f"  ERROR: {e.response.status_code} - {e.response.text}")
            except Exception as e:
                print(f"  ERROR: {e}")

        print("\nDone!")


if __name__ == "__main__":
    asyncio.run(main())
