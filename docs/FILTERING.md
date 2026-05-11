# Filtering Architecture

## Design

`currentFilters` is a **flat object** mapping column names to values:

```js
let currentFilters = {};
// Example: { "Dest Port": "80", "Source IP": "10.0.0.1" }
```

Filters are **global** — they apply across all tabs (Alert, DNS, HTTP, All Events, etc.). When a filter is set on one tab, it persists when switching to another tab.

Search (`currentSearch`) is a separate server-side full-text filter using SQLite FTS5. It is an **array of terms** — typing `tcp 80` creates two chips `[🔍 "tcp" ×] [🔍 "80" ×]`. Each chip is independently removable. Quoted phrases like `"GET /login"` become a single chip. Search terms AND together on the backend. Search complements column filters: you can search for `192.168.1.1` and then further narrow with aggregation filters. Search is cleared when loading a new PCAP or when clicking **Clear All**.

## Key Functions

| Function | Role |
|---|---|
| `performSearch()` | Splits `searchInput` into terms, pushes to `currentSearch` array, clears input, refreshes data |
| `clearSearch()` | Clears all `currentSearch` terms, resets input, refreshes data |
| `clearSearchTerm(index)` | Removes single term at index from `currentSearch`, refreshes data |
| `applyFilter(sectionId, columnName, value)` | Sets `currentFilters[columnName] = value`, rebuilds table + agg grid + stats + sankey |
| `clearFilter(columnName)` | Deletes `currentFilters[columnName]`, rebuilds |
| `clearAllFilters()` | Clears **both** `currentSearch` and `currentFilters`, refreshes data from server |
| `getFilteredEvents(sectionId, events, eventType)` | Returns events matching all active column filters |
| `buildSection(eventType, events)` | Builds the main data table, applies `currentFilters` internally |
| `buildAggregationsSection(eventType, events)` | Builds agg grid; **expects pre-filtered events** |
| `buildAllEvents()` | Builds "All Events" table, applies `currentFilters` internally |
| `buildAggregationsSectionAll()` | Builds agg grid for "All Events"; applies `currentFilters` internally |
| `updateFilterBarVisibility()` | Shows/hides the filter bar when search or filters exist |
| `buildStats(filteredStats)` | Rebuilds stats cards with filtered/total counts when constraints are active |
| `computeFilteredStats()` | Counts events by type from the filtered subset |
| `getSankeyEvents()` | Returns filtered events for the currently visible tab for the Sankey diagram |
| `refreshCurrentView()` | Rebuilds the current tab's table, aggregations, stats, filter bar, and Sankey diagram |
| `updateSankeyDiagram()` | Rebuilds the Sankey diagram using events from `getSankeyEvents()` |

## Data Flow

- `buildSection` / `buildAllEvents` apply `currentFilters` internally
- Filter bar is rendered by `updateFilterBarVisibility()` into `#filterBarContainer`
- `buildAggregationsSection` expects **pre-filtered events** from the caller
- `loadTabData` must call `getFilteredEvents()` before passing data to `buildAggregationsSection`
- `buildAggregationsSectionAll` applies `currentFilters` internally (exception to the pre-filtered rule)

## Column Overlap

Per-event-type columns differ from "All Events" columns:

| Shared columns | Per-type only | All-events only |
|---|---|---|
| Time, Protocol, Source IP, Source Port, Dest IP, Dest Port | Alert, Category, Severity, Query, Method, Host, URL, User-Agent, Status, SNI / Host, Version, Subject, Issuer, Pkts →, Pkts ←, Bytes →, Bytes ←, State, Alerted, Type (DNS record type) | Type (event type), Detail |

When filtering, both `extractValue()` and `extractAllValue()` handle all per-type columns. `extractAllValue()` supports the full set of per-type columns (Alert, Category, Severity, Query, Method, Host, URL, Status, User-Agent, SNI / Host, Version, Subject, Issuer, Pkts →, Pkts ←, Bytes →, Bytes ←, State, Alerted, Filename, Command, Message) so that a filter set on one tab (e.g., Alert on the Alerts tab) correctly matches events when switching to "All Events". Only truly unknown columns return `''`.

## Known Gotchas

### 1. `currentFilters` must stay flat
Nesting it as `{sectionId: {columnName: value}}` causes filters to disappear when switching tabs because each tab creates a new empty section entry. Tests enforce this:
- `test_currentFilters_is_flat_object_not_nested`
- `test_all_filtering_functions_use_global_currentFilters`

### 2. `buildAggregationsSection` expects pre-filtered events
When calling `buildAggregationsSection(eventType, events)` in aggregation mode, `events` must already be filtered through `getFilteredEvents()`. Passing raw events will show incorrect aggregation counts. Tests enforce this:
- `test_loadTabData_filters_agg_tables_in_advanced_mode_cached`
- `test_loadTabData_filters_agg_tables_in_advanced_mode_fresh`

### 3. Aggregation toggle must filter before building agg tables
When the user toggles Aggregation ON, the handler must call `getFilteredEvents()` before `buildAggregationsSection()`. See the `advancedToggle` change listener.

### 4. onclick quoting
Never use `JSON.stringify()` inside `onclick` attributes — it produces double-quoted strings that break inside double-quoted HTML attributes. Use single-quoted template expressions with escaped internal single quotes. Tests enforce this:
- `test_no_json_stringify_in_apply_filter_onclick`
- `test_no_json_stringify_in_clear_filter_onclick`
- `test_no_bare_json_stringify_in_onclick_templates`

## Running Tests

```bash
python3 -m unittest discover tests -v
```

All 431 tests must pass. The filtering-related tests are in:
- `TestFilterOnclickQuoting` (6 tests)
- `TestAdvancedModeFilterBar` (14 tests)
- `TestSearchUI` (22 tests)
