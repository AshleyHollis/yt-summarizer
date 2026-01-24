#!/bin/bash
# Install git hooks for the repository
# Run this script to set up pre-push hooks that validate code before pushing

set -e

echo "📦 Installing git hooks..."

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Install pre-push hook
cat > .git/hooks/pre-push << 'HOOKEOF'
#!/bin/bash
# Pre-push hook to run local checks before pushing code
# This prevents broken code from being pushed to remote

set -e

echo "🔍 Running pre-push checks..."

# Get the branch being pushed
currentBranch=$(git rev-parse --abbrev-ref HEAD)

# Skip checks for main branch (should use PR)
if [ "$currentBranch" = "main" ]; then
    echo "⚠️  Pushing directly to main - checks skipped"
    exit 0
fi

# Detect what changed
changedFiles=$(git diff --name-only origin/$currentBranch..HEAD 2>/dev/null || git diff --name-only --cached)

hasFrontend=$(echo "$changedFiles" | grep "^apps/web/" || true)
hasBackend=$(echo "$changedFiles" | grep "^services/\(api\|workers\|shared\)/" || true)

failed=0

# Frontend checks
if [ -n "$hasFrontend" ]; then
    echo ""
    echo "📦 Frontend changes detected - running comprehensive checks..."
    
    cd apps/web
    
    echo "  ├─ Running ESLint..."
    if npm run lint; then
        echo "  │  ✅ ESLint passed"
    else
        echo "  │  ❌ ESLint failed!"
        failed=1
    fi
    
    echo "  ├─ Running TypeScript check..."
    if npx tsc --noEmit; then
        echo "  │  ✅ TypeScript check passed"
    else
        echo "  │  ❌ TypeScript check failed!"
        failed=1
    fi
    
    echo "  ├─ Running build..."
    if npm run build; then
        echo "  │  ✅ Build passed"
    else
        echo "  │  ❌ Build failed!"
        failed=1
    fi
    
    echo "  └─ Running tests..."
    if npm run test:run; then
        echo "     ✅ Tests passed"
    else
        echo "     ❌ Tests failed!"
        failed=1
    fi
    
    cd ../..
fi

# Backend checks (Python)
if [ -n "$hasBackend" ]; then
    echo ""
    echo "🐍 Backend changes detected - running checks..."
    
    if echo "$changedFiles" | grep -q "^services/api/"; then
        echo "  ├─ Checking API..."
        cd services/api
        
        echo "  │  ├─ Running Ruff..."
        if uv run ruff check .; then
            echo "  │  │  ✅ Ruff passed"
        else
            echo "  │  │  ❌ Ruff failed!"
            failed=1
        fi
        
        echo "  │  └─ Running tests..."
        if uv run pytest tests/ -v; then
            echo "  │     ✅ Tests passed"
        else
            echo "  │     ❌ Tests failed!"
            failed=1
        fi
        
        cd ../..
    fi
    
    if echo "$changedFiles" | grep -q "^services/workers/"; then
        echo "  ├─ Checking Workers..."
        cd services/workers
        
        echo "  │  ├─ Running Ruff..."
        if uv run ruff check .; then
            echo "  │  │  ✅ Ruff passed"
        else
            echo "  │  │  ❌ Ruff failed!"
            failed=1
        fi
        
        echo "  │  └─ Running tests..."
        if uv run pytest tests/ -v; then
            echo "  │     ✅ Tests passed"
        else
            echo "  │     ❌ Tests failed!"
            failed=1
        fi
        
        cd ../..
    fi
    
    if echo "$changedFiles" | grep -q "^services/shared/"; then
        echo "  └─ Checking Shared..."
        cd services/shared
        
        echo "     ├─ Running Ruff..."
        if uv run ruff check .; then
            echo "     │  ✅ Ruff passed"
        else
            echo "     │  ❌ Ruff failed!"
            failed=1
        fi
        
        echo "     └─ Running tests..."
        if uv run pytest tests/ -v; then
            echo "        ✅ Tests passed"
        else
            echo "        ❌ Tests failed!"
            failed=1
        fi
        
        cd ../..
    fi
fi

# Final result
if [ $failed -eq 1 ]; then
    echo ""
    echo "❌ Pre-push checks FAILED! Fix errors before pushing."
    echo ""
    echo "💡 Tip: Run checks manually:"
    echo "   Frontend:"
    echo "     cd apps/web && npm run lint          # Lint check"
    echo "     cd apps/web && npx tsc --noEmit      # Type check"
    echo "     cd apps/web && npm run build         # Build check"
    echo "     cd apps/web && npm run test:run      # Tests"
    echo ""
    echo "   Backend:"
    echo "     cd services/<component> && uv run ruff check .  # Lint"
    echo "     cd services/<component> && uv run pytest tests/ # Tests"
    exit 1
fi

echo ""
echo "✅ All pre-push checks passed!"
exit 0
HOOKEOF

chmod +x .git/hooks/pre-push

echo "✅ Git hooks installed successfully!"
echo ""
echo "Pre-push hook will now run automatically before every push."
echo "It checks:"
echo "  - Frontend: ESLint, TypeScript, Build, and Tests"
echo "  - Backend: Ruff linting and Tests for API, Workers, and Shared"
echo ""
echo "To bypass the hook (not recommended): git push --no-verify"
