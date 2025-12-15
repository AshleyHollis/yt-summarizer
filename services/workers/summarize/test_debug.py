#!/usr/bin/env python3
"""Debug the settings to understand why mock summary isn't being used."""
import sys
sys.path.insert(0, "C:/Users/ashle/Source/GitHub/AshleyHollis/yt-summarizer/services/shared/src")

from shared.config import get_settings

settings = get_settings()
print(f"type: {type(settings.openai.api_key)}")
print(f"repr: {repr(settings.openai.api_key)}")
print(f"len: {len(settings.openai.api_key) if settings.openai.api_key else 0}")
print(f"not key: {not settings.openai.api_key}")
print(f"is 'not-configured': {settings.openai.api_key == 'not-configured'}")
print(f"should mock: {not settings.openai.api_key or settings.openai.api_key == 'not-configured'}")
