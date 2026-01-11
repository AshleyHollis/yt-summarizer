import sys
try:
    import yaml
except Exception as e:
    print('PyYAML not installed:', e)
    sys.exit(0)

files = ['.github/workflows/preview.yml', '.github/workflows/preview-test.yml']
for f in files:
    print('Parsing', f)
    try:
        with open(f, 'r', encoding='utf-8') as fh:
            yaml.safe_load(fh)
        print(' OK')
    except Exception as e:
        print(' ERROR:', e)
