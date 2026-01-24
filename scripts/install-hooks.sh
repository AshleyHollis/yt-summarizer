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
    echo "📦 Frontend changes detected - running checks..."
    
    cd apps/web
    echo "  ├─ Running ESLint..."
    if npm run lint; then
        echo "  └─ ✅ ESLint passed"
    else
        echo "  └─ ❌ ESLint failed!"
        failed=1
    fi
    cd ../..
fi

# Backend checks (Python)
if [ -n "$hasBackend" ]; then
    echo ""
    echo "🐍 Backend changes detected - running checks..."
    
    if echo "$changedFiles" | grep -q "^services/api/"; then
        echo "  ├─ Linting API code..."
        cd services/api
        if uv run ruff check .; then
            echo "  └─ ✅ Ruff check passed for API"
        else
            echo "  └─ ❌ Ruff check failed for API!"
            failed=1
        fi
        cd ../..
    fi
    
    if echo "$changedFiles" | grep -q "^services/workers/"; then
        echo "  ├─ Linting Workers code..."
        cd services/workers
        if uv run ruff check .; then
            echo "  └─ ✅ Ruff check passed for Workers"
        else
            echo "  └─ ❌ Ruff check failed for Workers!"
            failed=1
        fi
        cd ../..
    fi
    
    if echo "$changedFiles" | grep -q "^services/shared/"; then
        echo "  ├─ Linting Shared code..."
        cd services/shared
        if uv run ruff check .; then
            echo "  └─ ✅ Ruff check passed for Shared"
        else
            echo "  └─ ❌ Ruff check failed for Shared!"
            failed=1
        fi
        cd ../..
    fi
fi

# Final result
if [ $failed -eq 1 ]; then
    echo ""
    echo "❌ Pre-push checks FAILED! Fix errors before pushing."
    echo "💡 Tip: Run checks manually:"
    echo "   Frontend: cd apps/web && npm run lint"
    echo "   Backend:  cd services/<component> && uv run ruff check ."
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
echo "  - Frontend: ESLint (npm run lint)"
echo "  - Backend: Ruff linting for API, Workers, and Shared"
echo ""
echo "To bypass the hook (not recommended): git push --no-verify"
