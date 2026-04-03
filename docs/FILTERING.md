# Filtering Architecture

## Design

`currentFilters` is a **flat object** mapping column names to values:

```js
let currentFilters = {};
// Example: { "Dest Port": "80", "Source IP": "10.0.0.1" }
```

Filters are **global** — they apply across all tabs (Alert, DNS, HTTP, All Events, etc.). When a filter is set on one tab, it persists when switching to another tab.

## Key Functions

| Function | Role |
|---|---|
| `applyFilter(sectionId, columnName, value)` | Sets `currentFilters[columnName] = value`, rebuilds table + agg grid |
| `clearFilter(columnName)` | Deletes `currentFilters[columnName]`, rebuilds |
| `clearAllFilters()` | Resets `currentFilters = {}`, rebuilds |
| `getFilteredEvents(sectionId, events, eventType)` | Returns events matching all active filters |
| `buildSection(eventType, events)` | Builds the main data table, applies `currentFilters` internally |
| `buildAggregationsSection(eventType, events)` | Builds agg grid + filter bar in advanced mode; **expects pre-filtered events** |
| `buildAllEvents()` | Builds "All Events" table, applies `currentFilters` internally |
| `buildAggregationsSectionAll()` | Builds agg grid + filter bar for "All Events"; applies `currentFilters` internally |
| `updateFilterBarVisibility()` | Shows/hides the non-advanced mode filter bar |

## Data Flow

### Non-advanced mode
- `buildSection` / `buildAllEvents` apply `currentFilters` internally
- Filter bar is rendered by `updateFilterBarVisibility()` into `#filterBarContainer`

### Advanced mode
- `buildAggregationsSection` renders its own filter bar inside `#aggregations`
- **Important**: It expects **pre-filtered events** from the caller
- `loadTabData` must call `getFilteredEvents()` before passing data to `buildAggregationsSection`
- `buildAggregationsSectionAll` applies `currentFilters` internally (exception to the pre-filtered rule)

## Column Overlap

Per-event-type columns differ from "All Events" columns:

| Shared columns | Per-type only | All-events only |
|---|---|---|
| Time, Protocol, Source IP, Source Port, Dest IP, Dest Port | Alert, Category, Severity, Query, Method, URL, Status, User-Agent, SNI / Host, Version, Subject, Issuer, Pkts →, Pkts ←, Bytes →, Bytes ←, State, Alerted, Type (DNS record type) | Type (event type), Detail |

When filtering, `extractValue()` / `extractAllValue()` return `''` for columns that don't exist in the current view. The filter comparison `'' !== value` will exclude all events. This is expected behavior — a filter on "Severity" only makes sense on the Alerts tab.

## Known Gotchas

### 1. `currentFilters` must stay flat
Nesting it as `{sectionId: {columnName: value}}` causes filters to disappear when switching tabs because each tab creates a new empty section entry. Tests enforce this:
- `test_currentFilters_is_flat_object_not_nested`
- `test_all_filtering_functions_use_global_currentFilters`

### 2. `buildAggregationsSection` expects pre-filtered events
When calling `buildAggregationsSection(eventType, events)` in advanced mode, `events` must already be filtered through `getFilteredEvents()`. Passing raw events will show incorrect aggregation counts. Tests enforce this:
- `test_loadTabData_filters_agg_tables_in_advanced_mode_cached`
- `test_loadTabData_filters_agg_tables_in_advanced_mode_fresh`

### 3. Advanced toggle must filter before building agg tables
When the user toggles Advanced ON, the handler must call `getFilteredEvents()` before `buildAggregationsSection()`. See the `advancedToggle` change listener.

### 4. Dual filter bar rendering
- Non-advanced mode: filter bar in `#filterBarContainer` (managed by `updateFilterBarVisibility`)
- Advanced mode: filter bar inside `#aggregations` (managed by `buildAggregationsSection` / `buildAggregationsSectionAll`)
- Toggling between modes must clear the opposite container to prevent duplicate filter bars

### 5. onclick quoting
Never use `JSON.stringify()` inside `onclick` attributes — it produces double-quoted strings that break inside double-quoted HTML attributes. Use single-quoted template expressions with escaped internal single quotes. Tests enforce this:
- `test_no_json_stringify_in_apply_filter_onclick`
- `test_no_json_stringify_in_clear_filter_onclick`
- `test_no_bare_json_stringify_in_onclick_templates`

## Running Tests

```bash
python -m unittest test_ui -v
```

All 162 tests must pass. The filtering-related tests are in:
- `TestFilterOnclickQuoting` (6 tests)
- `TestAdvancedModeFilterBar` (14 tests)
