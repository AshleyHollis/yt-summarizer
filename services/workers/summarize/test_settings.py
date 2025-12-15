from shared.config import get_settings
s = get_settings()
key = s.openai.api_key
print(f"key=|{key}|")
print(f"is_empty={not key}")
print(f"check={not key or key == 'not-configured'}")
