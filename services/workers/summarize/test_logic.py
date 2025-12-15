import sys
sys.path.insert(0, ".")

from shared.config import get_settings

# Test the _generate_summary logic directly
async def test():
    settings = get_settings()
    print(f"API key: |{settings.openai.api_key}|")
    
    if not settings.openai.api_key or settings.openai.api_key == "not-configured":
        print("Would return mock summary")
        return "mock summary"
    else:
        print("Would try OpenAI API")
        return None

import asyncio
result = asyncio.run(test())
print(f"Result: {result}")
