# UI Design System

This document defines the consistent UI patterns used throughout the yt-summarizer application to ensure visual consistency, especially for interactive elements.

## Design Principles

1. **YouTube-inspired dark mode** - Red accent color (#ff0000 dark, #cc0000 light)
2. **Consistent hover states** - All interactive elements must have visible hover feedback
3. **Smooth transitions** - Use `transition-all 0.15s ease-out` or Tailwind's `transition-colors`
4. **Accessibility** - Focus rings using `var(--focus-ring)` for keyboard navigation
5. **Dark mode first** - Always consider both light and dark modes

---

## Color System

### CSS Custom Properties (defined in `globals.css`)

```css
/* Light mode */
:root {
  --background: #ffffff;
  --foreground: #0f0f0f;
  --card-bg: #ffffff;
  --card-border: #e5e5e5;
  --muted: #606060;
  --accent: #cc0000;           /* Primary red */
  --accent-light: #fee2e2;     /* Light red background */
  --hover-bg: rgba(0, 0, 0, 0.05);
  --active-bg: rgba(0, 0, 0, 0.1);
  --focus-ring: rgba(204, 0, 0, 0.4);
}

/* Dark mode */
.dark {
  --background: #0f0f0f;
  --foreground: #f1f1f1;
  --card-bg: #212121;
  --card-border: #3f3f3f;
  --muted: #aaaaaa;
  --accent: #ff0000;           /* Brighter red for dark mode */
  --accent-light: #3d0000;     /* Dark red background */
  --hover-bg: rgba(255, 255, 255, 0.1);
  --active-bg: rgba(255, 255, 255, 0.2);
  --focus-ring: rgba(255, 0, 0, 0.4);
}
```

### CopilotKit Variables (for chat sidebar components)

```css
--copilot-kit-primary-color       /* Red accent - #ff0000 (dark) / #cc0000 (light) */
--copilot-kit-contrast-color      /* White text on red */
--copilot-kit-background-color    /* Main background */
--copilot-kit-secondary-color     /* Secondary/elevated background */
--copilot-kit-secondary-contrast-color  /* Text on secondary background */
--copilot-kit-separator-color     /* Borders and dividers */
--copilot-kit-muted-color         /* Muted/helper text */
```

### Tailwind Color Mappings

| Semantic Use | Light Mode | Dark Mode |
|--------------|------------|-----------|
| Primary action | `red-600` | `red-500` |
| Primary hover | `red-700` | `red-600` |
| Error text | `red-600` | `red-400` |
| Error background | `red-50` | `red-900/30` |
| Error border | `red-200` | `red-800` |
| Success background | `green-50` | `green-900/30` |
| Warning background | `yellow-50` | `yellow-900/30` |
| Muted text | `gray-500` | `gray-400` |

---

## Button Patterns

### 1. Primary Button (Red Filled)

**Canonical Pattern:**
```tsx
className="px-4 py-2 bg-red-600 text-white text-sm font-medium rounded-lg
           hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed
           transition-colors"
```

**Used in:** Submit buttons, primary CTAs, "Chat with selected"

**Variations found (should be standardized):**
- ✅ `bg-red-600 hover:bg-red-700` - Standard
- ⚠️ `bg-red-500 hover:bg-red-600` - Slightly lighter variant (SelectionBar)
- ❌ `bg-red-600 hover:bg-red-500` - INCONSISTENT: lightens on hover (library/page.tsx)

### 2. Secondary Button (Outline/Ghost)

**Canonical Pattern:**
```tsx
className="px-3 py-1.5 text-sm font-medium rounded-lg
           border border-gray-300 dark:border-gray-600
           text-gray-700 dark:text-gray-300
           hover:bg-gray-100 dark:hover:bg-gray-800
           transition-colors"
```

**Used in:** "Select videos", Cancel buttons, secondary actions

### 3. Destructive/Exit Button (Red Outline)

**Canonical Pattern:**
```tsx
className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-lg
           border-2 border-red-500 bg-red-500/10
           text-red-600 dark:text-red-400
           hover:bg-red-500/20
           transition-colors"
```

**Used in:** "Exit selection" button

### 4. Icon Button (Toolbar Style)

**For CopilotKit components:**
```tsx
className="p-1.5 rounded-lg border border-transparent
           hover:border-[var(--copilot-kit-primary-color)]
           hover:bg-[var(--copilot-kit-secondary-color)]
           text-[var(--copilot-kit-muted-color)]
           hover:text-[var(--copilot-kit-primary-color)]
           transition-all duration-150"
```

**For main app:**
```tsx
className="p-2 rounded-lg text-gray-500 dark:text-gray-400
           hover:bg-gray-100 dark:hover:bg-gray-800
           hover:text-gray-900 dark:hover:text-white
           transition-colors"
```

### 5. Segmented Control Button (Active/Inactive)

**Active state:**
```tsx
className="bg-[var(--copilot-kit-primary-color)] text-white font-medium"
```

**Inactive state:**
```tsx
className="text-[var(--copilot-kit-muted-color)]
           hover:text-[var(--copilot-kit-secondary-contrast-color)]
           hover:bg-[var(--copilot-kit-background-color)]"
```

---

## Badge & Chip Patterns

### 1. Status Badge

```tsx
// Processing status badges
function getStatusBadgeClass(status: string): string {
  switch (status) {
    case 'completed': return 'bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300';
    case 'processing': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300';
    case 'pending': return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300';
    case 'failed': return 'bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300';
    default: return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
  }
}
```

### 2. Facet/Tag Chip

```tsx
className="inline-flex items-center rounded-full px-2.5 py-0.5
           text-xs font-medium bg-gray-100 dark:bg-gray-700
           text-gray-700 dark:text-gray-300"
```

### 3. Dismissible Badge (with X button)

**CSS Class available:** `.yt-badge-dismissible`

**Tailwind equivalent:**
```tsx
<button className="group/clear flex items-center gap-0.5 px-1.5 py-0.5
                   text-[10px] rounded
                   bg-[var(--copilot-kit-primary-color)] text-white font-medium
                   hover:brightness-110 transition-all">
  <span>3 Videos Selected</span>
  <span className="inline-flex items-center justify-center ml-0.5 rounded-sm
                   group-hover/clear:bg-white/20 transition-colors">
    <XMarkIcon className="h-2.5 w-2.5" />
  </span>
</button>
```

### 4. Count Badge (Notification Style)

```tsx
className="ml-1 px-1.5 py-0.5 text-xs font-bold rounded-full
           bg-red-500 text-white"
```

---

## Form Input Patterns

### 1. Text Input (Main App)

**Canonical Pattern:**
```tsx
className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600
           rounded-lg bg-white dark:bg-[#1a1a1a]
           text-gray-900 dark:text-white
           placeholder-gray-400
           hover:border-red-400
           focus:ring-2 focus:ring-red-500 focus:border-red-500
           focus:outline-none
           transition-all"
```

### 2. Filter Sidebar Input

**Canonical Pattern (Library filters):**
```tsx
className="block w-full rounded-xl
           border border-gray-200 dark:border-gray-700
           bg-gray-50/50 dark:bg-gray-800/50
           px-3 py-2.5 text-sm
           text-gray-900 dark:text-gray-100
           placeholder-gray-400 dark:placeholder-gray-500
           shadow-sm
           hover:border-red-400
           focus:border-red-400 focus:bg-white dark:focus:bg-gray-800
           focus:outline-none focus:ring-2 focus:ring-red-100 dark:focus:ring-red-900/30
           transition-all"
```

### 3. Select Dropdown

Same as Filter Sidebar Input with `appearance-none cursor-pointer`

---

## Card & Container Patterns

### 1. Video Card (Consistent with Chat UI)

```tsx
// Card with subtle background hover (like chat follow-up buttons)
className="group relative flex flex-col overflow-hidden rounded-xl
           border-2 bg-white dark:bg-[#1a1a1a]
           shadow-sm
           transition-all duration-150
           hover:bg-gray-50 dark:hover:bg-[#252525]"

// Selected state
className="border-red-500 dark:border-red-500 ring-2 ring-red-500/20"

// Default state
className="border-gray-200/60 dark:border-gray-700/60"

// Thumbnail hover effect
className="object-cover transition-transform duration-300 group-hover:scale-105"

// Duration badge (compact)
className="absolute bottom-2 right-2 rounded-md bg-black/80 backdrop-blur-sm px-1 py-0.5 text-xs font-medium text-white"
```

**Video Card Layout:**

```
┌─────────────────────────────────┐
│                       [Checkbox]│  ← Selection checkbox (top-right, selection mode only)
│                                 │
│      THUMBNAIL IMAGE            │  ← Zooms slightly on hover (scale-105)
│                                 │
│                        [12:34]  │  ← Duration badge (compact: px-1 py-0.5)
└─────────────────────────────────┘
│ [Status?] (only if not complete)│
│ Title text line 1               │  ← Full width, 2 lines max, tooltip on hover
│ Title text line 2               │  ← Turns red on hover (group-hover:text-red-500)
│ Channel name                    │  ← Muted text
│ 2 weeks ago                     │  ← Relative time
└─────────────────────────────────┘
```

**Layout rules:**
- **Grid:** 4 columns on desktop (`xl:grid-cols-4`), responsive down
- **Gap:** Tight spacing (`gap-3`)
- **Full width:** No max-width container constraint on library page
- **Card chrome:** Border + shadow + background (consistent with chat UI cards)
- **Hover:** Subtle background shift + thumbnail zoom (matches chat follow-up buttons)
- **Title hover:** Red color (`group-hover:text-red-500`)
- **Transition:** Fast 150ms for snappy feel

**Status Badge Visibility Rule:**
- ✅ `completed` → **Hide badge** (expected state, no action needed)
- ⏳ `pending` → Show yellow badge
- 🔄 `processing` → Show blue badge  
- ❌ `failed` → Show red badge

This follows the principle: *"Only surface information that requires attention."*

### 2. Content Card (Panels, Sections)

```tsx
className="rounded-lg border border-gray-200 dark:border-gray-700
           bg-white dark:bg-gray-800
           p-6"
```

### 3. Alert/Notification Box

**Error:**
```tsx
className="p-3 rounded-lg
           bg-red-50 dark:bg-red-900/30
           border border-red-200 dark:border-red-800"
```

**Success:**
```tsx
className="p-4 rounded-lg
           bg-green-50 dark:bg-green-900/30
           border border-green-200 dark:border-green-800"
```

**Warning:**
```tsx
className="p-3 rounded-lg
           bg-yellow-50 dark:bg-yellow-900/30
           border border-yellow-200 dark:border-yellow-800"
```

---

## Link Patterns

### 1. Navigation Link (Navbar)

```tsx
className="rounded-lg px-3 py-1.5 text-sm font-medium transition-colors"
// Active: bg-red-500 text-white (solid red, white text)
// Inactive: text-gray-600 dark:text-gray-400 hover:bg-red-500/10 hover:text-red-500 dark:hover:text-red-400
```

### 2. Inline Text Link (in paragraphs)

```tsx
className="text-red-600 dark:text-red-400
           hover:text-red-700 dark:hover:text-red-300
           hover:underline
           transition-colors"
```

### 3. Citation Link (in chat)

```tsx
className="text-red-500 font-semibold ml-0.5
           hover:text-red-600
           transition-colors"
```

---

## Hover Effect Patterns

### Standard Approaches

| Effect Type | Tailwind Classes |
|-------------|------------------|
| Background lightening | `hover:bg-gray-50 dark:hover:bg-[#252525]` (cards) or `hover:bg-gray-100 dark:hover:bg-gray-800` (buttons) |
| Red border appear | `border border-transparent hover:border-red-400` |
| Brightness boost | `hover:brightness-110 transition-all` |
| Text color change | `hover:text-[var(--copilot-kit-primary-color)]` |
| Scale up | `hover:scale-105 transition-transform` |
| Card lift | `hover:-translate-y-1 hover:shadow-xl` |

### X/Dismiss Icon Hover (Group Pattern)

```tsx
// Parent button
<button className="group/clear ...">
  {/* X icon wrapper */}
  <span className="group-hover/clear:bg-white/20 transition-colors rounded-sm">
    <XMarkIcon />
  </span>
</button>
```

---

## Transition Standards

| Duration | Use Case |
|----------|----------|
| `transition-colors` | Simple color/background changes |
| `transition-all` | Multiple property changes |
| `transition-all duration-150` | Standard interactive elements |
| `transition-all duration-300` | Cards, larger UI movements |
| `transition-all duration-500` | Progress bars, loading states |

---

## Focus States

### Standard Focus Ring

```tsx
className="focus:outline-none focus:ring-2 focus:ring-red-500"
// Or with offset:
className="focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
```

### CopilotKit Components (via CSS)

Uses `focus-visible:outline` with `var(--focus-ring)`

---

## Consistency Standards

All UI patterns in this codebase follow these standards. Deviations should be flagged and fixed.

| Pattern | Standard | Anti-Pattern |
|---------|----------|--------------|
| Primary button hover | `bg-red-600 hover:bg-red-700` | `hover:bg-red-500` (lighter) |
| Focus ring color | `focus:ring-red-500` | `focus:ring-blue-500` |
| Dark mode | All components must have `dark:` variants | Hardcoded light-only colors |
| Transitions | `transition-colors` or `transition-all` | No transition on interactive elements |
| Brand colors | `red-600`/`red-700` for actions | `indigo-600`, `blue-600` for primary actions |
| Nav active state | `bg-red-500 text-white` | `bg-gray-100 text-gray-900` |
| Interactive links | `text-red-600 hover:text-red-700` | `text-blue-600`, `text-indigo-600` |
| Loading spinners | `text-red-600` | `text-blue-600` |

**Last verified:** January 2026 — All inconsistencies resolved.

---

## CSS Utility Classes Available

From `globals.css`:

| Class | Purpose |
|-------|---------|
| `.yt-interactive-box` | Cards and clickable containers |
| `.yt-pill-button` | YouTube-style chip buttons |
| `.yt-btn-primary` | Red primary action button |
| `.yt-badge-dismissible` | Filled badge with X button |
| `.yt-badge-dismissible-outline` | Outlined dismissible badge |
| `.yt-icon-button` | Toolbar-style icon buttons |
| `.yt-input` | Standard text input |
| `.yt-link` | Text links with hover effect |

---

## Accessibility Checklist

When adding new interactive elements:

- [ ] **Hover state** - Element changes visually on hover
- [ ] **Focus state** - Visible focus ring for keyboard navigation
- [ ] **Transition** - Smooth animation between states
- [ ] **Dark mode** - Tested in both light and dark themes
- [ ] **Contrast** - Text meets WCAG AA contrast ratio
- [ ] **Touch target** - Minimum 44x44px for mobile

---

## Additional Component Patterns

### Floating Selection Bar

The floating bar that appears when videos are selected in the library:

```tsx
// Container
className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 animate-in slide-in-from-bottom-4 duration-300"

// Bar styling
className="flex items-center gap-3 px-4 py-3 bg-gray-900/95 dark:bg-gray-800/95 backdrop-blur-lg rounded-2xl shadow-2xl shadow-black/30 border border-gray-700/50"

// Count badge
className="w-8 h-8 rounded-lg bg-red-500 flex items-center justify-center"

// Thumbnail strip
className="w-12 h-8 rounded-md overflow-hidden ring-2 ring-gray-600 hover:ring-red-500 transition-all"

// Primary action button
className="flex items-center gap-1.5 px-4 py-1.5 text-sm font-semibold text-white bg-red-600 hover:bg-red-700 rounded-lg transition-colors shadow-lg shadow-red-600/25"

// Secondary action
className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
```

### Filter Sidebar

The filter panel on the library page:

```tsx
// Container
className="sticky top-20 rounded-2xl border border-gray-300 dark:border-gray-700/60 bg-white dark:bg-[#1a1a1a]/80 backdrop-blur-sm p-5 shadow-md dark:shadow-black/20"

// Section header icon container
className="w-8 h-8 rounded-lg bg-gradient-to-br from-slate-100 to-gray-200 dark:from-gray-700 dark:to-gray-800 flex items-center justify-center"

// Section label
className="text-xs font-medium text-gray-600 dark:text-gray-300 uppercase tracking-wider"

// Clear filters link
className="text-xs font-medium text-red-500 hover:text-red-400 transition-colors"
```

### Pagination

```tsx
// Active page
className="z-10 bg-red-600 text-white focus:z-20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600"

// Inactive page
className="text-gray-900 dark:text-gray-100 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 focus:z-20 focus:outline-offset-0"

// Disabled nav button
className="text-gray-300 dark:text-gray-600 cursor-not-allowed bg-gray-50 dark:bg-gray-900"

// Results count text
className="text-sm text-gray-700 dark:text-gray-300"
```

### Loading Skeleton

```tsx
// Video card skeleton
className="rounded-xl border-2 border-gray-200/60 dark:border-gray-700/60 bg-white dark:bg-[#1a1a1a] overflow-hidden"

// Thumbnail skeleton
className="aspect-video animate-pulse bg-gradient-to-r from-gray-200 via-gray-100 to-gray-200 dark:from-gray-800 dark:via-gray-700 dark:to-gray-800"

// Text skeleton lines
className="h-4 w-full animate-pulse rounded bg-gray-200 dark:bg-gray-700"
className="h-4 w-3/4 animate-pulse rounded bg-gray-200 dark:bg-gray-700"
className="h-3 w-1/2 animate-pulse rounded bg-gray-200 dark:bg-gray-700"
```

### Empty State

```tsx
// Container
className="rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800/50 p-12 text-center shadow-sm"

// Icon container
className="mx-auto w-16 h-16 rounded-full bg-gray-100 dark:bg-gray-700 flex items-center justify-center mb-4"

// Icon
className="w-8 h-8 text-gray-400 dark:text-gray-500"

// Title
className="text-lg font-medium text-gray-900 dark:text-gray-100"

// Description
className="mt-2 text-sm text-gray-600 dark:text-gray-300"
```

### Transcript Segment List

```tsx
// Segment card
className="group flex gap-3 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800/50 p-4 transition-colors hover:border-red-200 dark:hover:border-red-700 hover:bg-red-50/50 dark:hover:bg-red-900/20"

// Timestamp button
className="flex shrink-0 items-center gap-1.5 rounded-md bg-gray-100 dark:bg-gray-700 px-2.5 py-1.5 text-sm font-medium text-gray-700 dark:text-gray-300 transition-colors hover:bg-red-100 dark:hover:bg-red-900/50 hover:text-red-700 dark:hover:text-red-300 group-hover:bg-red-100 dark:group-hover:bg-red-900/50 group-hover:text-red-700 dark:group-hover:text-red-300"

// Segment text
className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed"

// Time range
className="text-xs text-gray-400 dark:text-gray-500"
```

### AI Summary Box

```tsx
// Container
className="mt-6 rounded-lg bg-red-50 dark:bg-red-900/30 p-4"

// Title
className="text-sm font-medium text-red-900 dark:text-red-300"

// Content
className="mt-2 whitespace-pre-wrap text-sm text-red-800 dark:text-red-200"
```

### Follow-up Questions (Chat UI)

```tsx
// Container (with hover border effect)
className="space-y-3 bg-[var(--copilot-kit-secondary-color)] rounded-xl p-4 border border-[var(--copilot-kit-separator-color)] hover:border-[var(--copilot-kit-primary-color)] transition-all duration-150"

// Header
className="text-sm font-semibold text-[var(--copilot-kit-secondary-contrast-color)] flex items-center gap-2"

// Individual question button (subtle hover)
className="group flex items-start gap-3 rounded-lg border border-[var(--copilot-kit-separator-color)] bg-[var(--copilot-kit-background-color)] px-3 py-3 text-sm text-[var(--copilot-kit-secondary-contrast-color)] hover:border-[var(--copilot-kit-primary-color)] transition-all duration-150 cursor-pointer text-left"

// Arrow icon
className="text-[var(--copilot-kit-primary-color)] shrink-0 pt-0.5 text-sm font-semibold"
```

### Explanation Panel

```tsx
// Container
className="mt-3 p-3 bg-gradient-to-r from-red-50 to-rose-50 dark:from-red-900/20 dark:to-rose-900/20 border border-red-200/60 dark:border-red-700/40 rounded-lg animate-in slide-in-from-top-2 duration-200"

// Icon
className="w-4 h-4 text-red-600 dark:text-red-400 mt-0.5 flex-shrink-0"

// Summary text
className="text-sm text-gray-800 dark:text-gray-200 leading-relaxed"
```

### Key Moments List

```tsx
// Timestamp link
className="inline-flex items-center gap-1.5 text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 hover:underline"

// Timestamp badge
className="font-mono text-xs bg-red-100 dark:bg-red-900/50 px-1.5 py-0.5 rounded"

// Description
className="text-gray-700 dark:text-gray-300 text-xs truncate max-w-[200px]"
```

### Loading Spinner

```tsx
// Standard loading spinner (uses brand red)
<svg className="animate-spin h-8 w-8 text-red-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
</svg>
```

---

## Semantic Status Colors

These colors are intentionally NOT red - they indicate system status:

| Status | Background | Text | Use Case |
|--------|------------|------|----------|
| Pending | `bg-gray-50` / `bg-gray-800` | `text-gray-600` | Jobs waiting |
| Running/Processing | `bg-blue-50` / `bg-blue-900/30` | `text-blue-600` | Active processes |
| Completed/Success | `bg-green-50` / `bg-green-900/30` | `text-green-600` | Finished successfully |
| Failed/Error | `bg-red-50` / `bg-red-900/30` | `text-red-600` | Errors |
| Warning | `bg-yellow-50` / `bg-yellow-900/30` | `text-yellow-600` | Warnings |

**Note:** Blue is acceptable for "processing" status indicators as it's a semantic color indicating activity, distinct from the red brand color used for interactive elements.

---

## Animation Classes

```css
/* Entry animations (from Tailwind CSS animate plugin) */
.animate-in { }
.slide-in-from-bottom-4 { }
.slide-in-from-top-2 { }
.duration-200 { }
.duration-300 { }

/* Loading animations */
.animate-spin { }
.animate-pulse { }
```

---

## Z-Index Scale

| Layer | Z-Index | Use Case |
|-------|---------|----------|
| Base content | 0 | Regular page content |
| Sticky elements | 20 | Selection checkboxes on cards |
| Sidebar sticky | 20 | Filter sidebar |
| Navbar | 40 | Top navigation |
| Floating bar | 50 | Selection bar at bottom |
| Modals/Dialogs | 100+ | Modal overlays |
