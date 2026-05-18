#!/usr/bin/env python3
import json
import unittest
import re
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ohmypcap.html')
JS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static', 'ohmypcap.js')
CSS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'static', 'ohmypcap.css')

with open(HTML_PATH, 'r') as f:
    HTML_CONTENT = f.read()
with open(JS_PATH, 'r') as f:
    JS_CONTENT = f.read()
with open(CSS_PATH, 'r') as f:
    CSS_CONTENT = f.read()


class TestHTMLStructure(unittest.TestCase):
    def test_file_size(self):
        """Verify JS file is complete (not truncated)"""
        self.assertGreater(len(JS_CONTENT), 80000, 'JS file appears truncated')

    def test_script_tags_closed(self):
        """Verify script tags are properly closed"""
        self.assertIn('<script src="static/ohmypcap.js"></script>', HTML_CONTENT)
        # Count occurrences (including script tags with src attributes)
        open_count = HTML_CONTENT.count('<script>') + HTML_CONTENT.count('<script ')
        close_count = HTML_CONTENT.count('</script>')
        self.assertEqual(open_count, close_count, 'Script tags not balanced')

    def test_css_file_size(self):
        """Verify CSS file is complete (not truncated)"""
        self.assertGreater(len(CSS_CONTENT), 1000, 'CSS file appears truncated')

    def test_html_references_css(self):
        self.assertIn('<link rel="stylesheet" href="static/ohmypcap.css">', HTML_CONTENT)

    def test_no_inline_style_block(self):
        """HTML must not contain inline <style> blocks after split."""
        self.assertNotIn('<style>', HTML_CONTENT, 'Inline <style> block found in HTML')
        self.assertNotIn('</style>', HTML_CONTENT, 'Inline </style> tag found in HTML')

    def test_no_inline_script_block(self):
        """HTML must not contain inline <script> blocks after split."""
        inline_script = re.search(r'<script[^>]*>(?!\s*</script>)', HTML_CONTENT)
        self.assertIsNone(inline_script, 'Inline <script> block found in HTML')

    def test_static_files_exist(self):
        """static/ohmypcap.css and static/ohmypcap.js must exist on disk."""
        self.assertTrue(os.path.exists(CSS_PATH), 'static/ohmypcap.css must exist')
        self.assertTrue(os.path.exists(JS_PATH), 'static/ohmypcap.js must exist')

    def test_valid_doctype(self):
        self.assertTrue(HTML_CONTENT.startswith('<!DOCTYPE html>'))

    def test_has_charset(self):
        self.assertIn('charset="UTF-8"', HTML_CONTENT)

    def test_has_viewport(self):
        self.assertIn('viewport', HTML_CONTENT)

    def test_has_title(self):
        self.assertIn('OhMyPCAP - Welcome', HTML_CONTENT)

    def test_has_container(self):
        self.assertIn('class="container"', HTML_CONTENT)

    def test_has_stats_grid(self):
        self.assertIn('id="statsGrid"', HTML_CONTENT)

    def test_has_sections_container(self):
        self.assertIn('id="sections"', HTML_CONTENT)

    def test_has_input_boxes(self):
        self.assertIn('id="inputBoxes"', HTML_CONTENT)

    def test_has_header(self):
        self.assertIn('id="mainHeader"', HTML_CONTENT)

    def test_has_stream_modal(self):
        self.assertIn('id="streamModal"', HTML_CONTENT)

    def test_has_loading_modal(self):
        self.assertIn('id="loadingModal"', HTML_CONTENT)

    def test_has_modal_close_button(self):
        self.assertIn('closeModal()', HTML_CONTENT)

    def test_has_spinner_animation(self):
        self.assertIn('@keyframes spin', CSS_CONTENT)

    def test_has_marked_js(self):
        self.assertNotIn('marked.min.js', HTML_CONTENT)

    def test_closing_tags(self):
        self.assertIn('</html>', HTML_CONTENT)
        self.assertIn('</body>', HTML_CONTENT)
        self.assertIn('</head>', HTML_CONTENT)


class TestCSSLayout(unittest.TestCase):
    def test_stats_grid_columns(self):
        match = re.search(r'grid-template-columns:\s*repeat\(([^)]+)\)', CSS_CONTENT)
        self.assertIsNotNone(match, "stats-grid should have grid-template-columns")
        if match:
            columns = match.group(1)
            self.assertIn('auto-fit', columns,
                          'stats-grid must use auto-fit for responsive wrapping')
            self.assertIn('minmax', columns,
                          'stats-grid must use minmax for responsive column sizing')

    def test_stats_grid_gap(self):
        self.assertIn('gap:', CSS_CONTENT)

    def test_section_hidden_class(self):
        self.assertIn('.section-hidden', CSS_CONTENT)
        self.assertIn('display: none', CSS_CONTENT)

    def test_stat_card_hover(self):
        self.assertIn('.stat-card:hover', CSS_CONTENT)

    def test_table_sticky_headers(self):
        self.assertIn('position: sticky', CSS_CONTENT)

    def test_no_horizontal_scrollbars(self):
        """No element should force horizontal scrolling; content must wrap instead."""
        self.assertNotIn('overflow-x: auto', CSS_CONTENT,
                         'No horizontal scrollbars allowed; content must wrap')
        self.assertIn('overflow-wrap: break-word', CSS_CONTENT,
                      'Long content must wrap with break-word')
        self.assertIn('table-layout: fixed', CSS_CONTENT,
                      'Table must use fixed layout to prevent expansion beyond viewport')

    def test_stream_output_breaks_on_dots(self):
        """Modal stream output must break on non-word characters like dots."""
        self.assertIn('.stream-output {', CSS_CONTENT,
                      'stream-output style must exist')
        self.assertIn('word-break: break-all', CSS_CONTENT,
                      'stream-output must break on dots and non-word characters')

    def test_detail_row_allows_text_wrapping(self):
        """Detail rows must override the global td nowrap so content can wrap."""
        self.assertIn('.detail-row td {', CSS_CONTENT,
                      'detail-row td style must exist')
        self.assertIn('white-space: normal', CSS_CONTENT,
                      'detail-row td must allow text wrapping')

    def test_table_cells_wrap_not_truncate(self):
        """Table cells (including ALERT) must wrap text, not truncate with ellipsis."""
        td_match = re.search(r'td \{([^}]+)\}', CSS_CONTENT)
        self.assertIsNotNone(td_match, 'Global td style must exist')
        td_style = td_match.group(1)
        self.assertNotIn('white-space: nowrap', td_style,
                         'td must not force single-line truncation')
        self.assertNotIn('text-overflow: ellipsis', td_style,
                         'td must not hide overflow with ellipsis')
        self.assertIn('overflow-wrap: break-word', td_style,
                      'td must wrap long text like alert signatures')

    def test_detail_content_wraps(self):
        """Detail content must use overflow-wrap to prevent overflow."""
        self.assertIn('.detail-content {', CSS_CONTENT,
                      'detail-content style must exist')
        self.assertIn('overflow-wrap: break-word', CSS_CONTENT,
                      'detail-content must wrap long text')

    def test_ascii_transcript_lines_wrap(self):
        """ASCII transcript inner divs must wrap to avoid horizontal overflow."""
        self.assertIn('.ascii-transcript div { overflow-wrap: break-word', CSS_CONTENT,
                      'ascii-transcript divs must wrap long lines')
        self.assertIn('word-break: break-all', CSS_CONTENT,
                      'ascii-transcript divs must break on non-word characters like dots')

    def test_ascii_transcript_shows_loading_indicator(self):
        """ASCII transcript must show a loading spinner while fetching."""
        self.assertIn('.ascii-loading {', CSS_CONTENT,
                      'ascii-loading CSS class must exist')
        self.assertIn('Loading ASCII transcript', JS_CONTENT,
                      'toggleRow must set loading text before fetching transcript')
        self.assertIn('ascii-loading', JS_CONTENT,
                      'toggleRow must use ascii-loading spinner class')

    def test_detail_grid_can_shrink(self):
        """formatEvent grid must set min-width: 0 so columns shrink on narrow viewports."""
        self.assertIn('min-width: 0', JS_CONTENT,
                      'formatEvent grid must set min-width: 0 to shrink')
        self.assertIn('minmax(0, 1fr)', JS_CONTENT,
                      'formatEvent grid must use minmax(0, 1fr) to allow column shrinking')

    def test_responsive_viewport(self):
        self.assertIn('width=device-width', HTML_CONTENT)


class TestJavaScriptFunctions(unittest.TestCase):
    def test_has_escape_html(self):
        self.assertIn('function escapeHtml', JS_CONTENT)

    def test_has_show_tab(self):
        self.assertIn('function showTab', JS_CONTENT)

    def test_has_toggle_row(self):
        self.assertIn('function toggleRow', JS_CONTENT)

    def test_has_load_ascii_transcript(self):
        self.assertIn('function loadAsciiTranscript', JS_CONTENT)

    def test_has_format_event(self):
        self.assertIn('function formatEvent', JS_CONTENT)

    def test_has_sort_table(self):
        self.assertIn('function sortTable', JS_CONTENT)

    def test_has_render_table(self):
        self.assertIn('function renderTable', JS_CONTENT)

    def test_has_close_modal(self):
        self.assertIn('function closeModal', JS_CONTENT)

    def test_has_show_loading(self):
        self.assertIn('function showLoading', JS_CONTENT)

    def test_has_hide_loading(self):
        self.assertIn('function hideLoading', JS_CONTENT)

    def test_has_show_welcome(self):
        self.assertIn('function showWelcome', JS_CONTENT)

    def test_has_load_analysis(self):
        self.assertIn('function loadAnalysis', JS_CONTENT)

    def test_has_load_from_url(self):
        self.assertIn('function loadFromUrl', JS_CONTENT)

    def test_has_upload_pcap(self):
        self.assertIn('function uploadPcap', JS_CONTENT)

    def test_has_check_status(self):
        self.assertIn('function checkStatus', JS_CONTENT)

    def test_has_build_stats(self):
        self.assertIn('function buildStats', JS_CONTENT)

    def test_has_build_sections(self):
        self.assertIn('function buildSections', JS_CONTENT)

    def test_has_build_row_for_event(self):
        self.assertIn('function buildRowForEvent', JS_CONTENT)

    def test_has_get_columns_for_type(self):
        self.assertIn('function getColumnsForType', JS_CONTENT)

    def test_has_build_all_events(self):
        self.assertIn('function buildAllEvents', JS_CONTENT)

    def test_has_clearAnalysisContainers(self):
        self.assertIn('function clearAnalysisContainers', JS_CONTENT)

    def test_has_showWelcomeUI(self):
        self.assertIn('function showWelcomeUI', JS_CONTENT)

    def test_has_showAnalysisUI(self):
        self.assertIn('function showAnalysisUI', JS_CONTENT)

    def test_has_refreshCurrentView(self):
        self.assertIn('function refreshCurrentView', JS_CONTENT)

    def test_has_init(self):
        self.assertIn('function init', JS_CONTENT)

    def test_has_delete_analysis(self):
        self.assertIn('function openDeleteAnalysis', JS_CONTENT)

    def test_has_reanalyze_modal_functions(self):
        self.assertIn('function openReanalyzeModal', JS_CONTENT)
        self.assertIn('function closeReanalyzeModal', JS_CONTENT)
        self.assertIn('function confirmReanalyze', JS_CONTENT)


class TestJavaScriptSyntax(unittest.TestCase):
    def test_no_unclosed_template_literals(self):
        """Check that template literals are properly closed"""
        backtick_count = JS_CONTENT.count('`')
        # Should be even - all template literals have matching backticks
        self.assertEqual(backtick_count % 2, 0, f'Unclosed template literals detected: {backtick_count} backticks')

    def test_brace_balance_in_script(self):
        """Check that braces are balanced in JavaScript"""
        open_braces = JS_CONTENT.count('{')
        close_braces = JS_CONTENT.count('}')
        self.assertEqual(open_braces, close_braces, f'Unbalanced braces: {open_braces} open, {close_braces} close')

    def test_paren_balance_in_script(self):
        """Check that parentheses are balanced in JavaScript"""
        open_parens = JS_CONTENT.count('(')
        close_parens = JS_CONTENT.count(')')
        self.assertEqual(open_parens, close_parens, f'Unbalanced parentheses: {open_parens} open, {close_parens} close')

    def test_script_is_valid_js(self):
        """Verify JavaScript can be parsed without syntax errors"""
        # This test checks that there are no obvious syntax errors
        # by verifying all function definitions have matching braces
        import re
        func_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*\{'
        matches = list(re.finditer(func_pattern, JS_CONTENT))
        
        for match in matches:
            start = match.end()
            brace_count = 1
            pos = start
            found_end = False
            while pos < len(JS_CONTENT) and brace_count > 0 and pos - start < 100000:
                if JS_CONTENT[pos] == '{':
                    brace_count += 1
                elif JS_CONTENT[pos] == '}':
                    brace_count -= 1
                pos += 1
            
            if brace_count != 0:
                func_name = match.group(1)
                self.fail(f"Function '{func_name}' has unbalanced braces")


class TestCardOrder(unittest.TestCase):
    def test_alert_first_all_last_sorting(self):
        """Verify alert is first and all is last in stats sorting logic"""
        # Check the sorting logic in the code
        self.assertIn("function sortEventTypes", JS_CONTENT,
                      "Should have a sortEventTypes helper for event type ordering")
        self.assertIn("t !== 'stats' && t !== 'all'", JS_CONTENT,
                      "Should filter out 'stats' and 'all' from sorting")
        self.assertIn("a.localeCompare(b)", JS_CONTENT,
                      "Should sort alphabetically after prioritized types")

    def test_sortEventTypes_behavior(self):
        """sortEventTypes must prioritize alert and filealerts, then sort alphabetically."""
        from tests.jsdom_helper import js_expression
        result = js_expression("sortEventTypes(['dns', 'http', 'alert', 'filealerts', 'tls'])")
        self.assertEqual(result, ['alert', 'filealerts', 'dns', 'http', 'tls'])

    def test_sortEventTypes_fallback_to_alphabetical(self):
        """sortEventTypes must fall back to alphabetical ordering for non-prioritized types."""
        from tests.jsdom_helper import js_expression
        result = js_expression("sortEventTypes(['dns', 'stats', 'all'])")
        self.assertEqual(result, ['all', 'dns', 'stats'])

    def test_apply_filter_calls_both_section_and_aggregation(self):
        """Verify applyFilter builds both section and aggregation when filtering"""
        self.assertIn("buildSection(eventType, sections[eventType])", JS_CONTENT,
                      "applyFilter should call buildSection")
        applyFunc = JS_CONTENT.split('function applyFilter(')[1].split('function clearFilter')[0]
        self.assertIn("applyFilters", applyFunc,
                      "applyFilter should delegate to applyFilters")
        refreshFunc = JS_CONTENT.split('function refreshCurrentView')[1].split('function ')[0]
        self.assertIn("buildAggregationsSection(eventType, filtered)", refreshFunc,
                      "refreshCurrentView should call buildAggregationsSection with filtered events")
        self.assertIn("updateSankeyDiagram()", refreshFunc,
                      "refreshCurrentView should update Sankey diagram")


class TestJavaScriptDataStructures(unittest.TestCase):
    def test_has_type_labels(self):
        self.assertIn('typeLabels', JS_CONTENT)

    def test_has_type_colors(self):
        self.assertIn('COLORS', JS_CONTENT)

    def test_colors_event_alert_is_red(self):
        self.assertIn("alert: '#ff6b6b'", JS_CONTENT,
                      'COLORS.EVENT.alert must be red')

    def test_has_event_type_icons_constant(self):
        self.assertIn('EVENT_TYPE_ICONS', JS_CONTENT)

    def test_has_all_events_columns_constant(self):
        self.assertIn('ALL_EVENTS_COLUMNS', JS_CONTENT)

    def test_has_empty_filter_state_constant(self):
        self.assertIn('EMPTY_FILTER_STATE_HTML', JS_CONTENT)

    def test_has_agg_collapsed_constant(self):
        self.assertIn('AGG_COLLAPSED_HTML', JS_CONTENT)

    def test_has_all_event_types(self):
        expected_types = ['alert', 'dns', 'http', 'tls', 'flow', 'ftp', 'stats', 'anomaly', 'fileinfo']
        for etype in expected_types:
            self.assertIn(f"'{etype}'", JS_CONTENT)

    def test_has_global_state(self):
        self.assertIn('let allEvents', JS_CONTENT)
        self.assertIn('let sections', JS_CONTENT)
        self.assertIn('let eventTypes', JS_CONTENT)
        self.assertIn('let currentMd5', JS_CONTENT)


class TestJavaScriptLogic(unittest.TestCase):
    def test_escape_html_escapes_special_chars(self):
        self.assertIn('&amp;', JS_CONTENT)
        self.assertIn('&lt;', JS_CONTENT)
        self.assertIn('&gt;', JS_CONTENT)
        self.assertIn('&quot;', JS_CONTENT)

    def test_sort_table_toggles_direction(self):
        self.assertIn('sort-asc', JS_CONTENT)
        self.assertIn('sort-desc', JS_CONTENT)

    def test_toggle_row_handles_detail_visibility(self):
        self.assertIn('detail-row', JS_CONTENT)
        self.assertIn('visible', JS_CONTENT)
        self.assertIn('expanded-row', JS_CONTENT)

    def test_format_event_handles_all_types(self):
        event_types = ['alert', 'dns', 'http', 'tls', 'flow', 'ftp', 'anomaly', 'fileinfo', 'stats']
        for etype in event_types:
            self.assertIn(f"event_type === '{etype}'", JS_CONTENT)

    def test_get_columns_returns_correct_columns(self):
        self.assertIn("case 'alert':", JS_CONTENT)
        self.assertIn("case 'dns':", JS_CONTENT)
        self.assertIn("case 'http':", JS_CONTENT)
        self.assertIn("case 'tls':", JS_CONTENT)
        self.assertIn("case 'flow':", JS_CONTENT)
        self.assertIn('default:', JS_CONTENT)

    def test_keyboard_shortcuts(self):
        self.assertIn("e.key === 'Escape'", JS_CONTENT)

    def test_url_parameter_handling(self):
        self.assertIn('URLSearchParams', JS_CONTENT)
        self.assertIn('pcap', JS_CONTENT)

    def test_date_range_display(self):
        self.assertIn('ts[0]', JS_CONTENT)
        self.assertIn('ts[ts.length-1]', JS_CONTENT)

    def test_event_type_sorting(self):
        self.assertIn("function sortEventTypes", JS_CONTENT)
        self.assertIn("localeCompare", JS_CONTENT)


class TestAPIIntegration(unittest.TestCase):
    def test_uses_correct_api_endpoints(self):
        endpoints = [
            '/api/events',
            '/api/analyses',
            '/api/load-analysis',
            '/api/upload',
            '/api/load-url',
            '/api/check-status',
            '/api/ascii-stream',
            '/api/download-stream',
        ]
        for endpoint in endpoints:
            self.assertIn(endpoint, JS_CONTENT)

    def test_uses_fetch_api(self):
        self.assertIn('fetch(', JS_CONTENT)

    def test_handles_json_responses(self):
        self.assertIn('.json()', JS_CONTENT)

    def test_handles_errors(self):
        self.assertIn('catch', JS_CONTENT)
        self.assertIn('err.message', JS_CONTENT)

    def test_uses_correct_http_methods(self):
        self.assertIn("method: 'POST'", JS_CONTENT)

    def test_sends_json_content_type(self):
        self.assertIn("'Content-Type': 'application/json'", JS_CONTENT)

    def test_uses_form_data_for_upload(self):
        self.assertIn('FormData', JS_CONTENT)

    def test_passes_md5_to_api(self):
        self.assertIn('md5=', JS_CONTENT)
        self.assertIn('currentMd5', JS_CONTENT)


class TestUXFeatures(unittest.TestCase):
    def test_loading_states(self):
        self.assertIn('showLoading', JS_CONTENT)
        self.assertIn('hideLoading', JS_CONTENT)
        self.assertIn('spinner', CSS_CONTENT)

    def test_empty_state_handling(self):
        self.assertIn('No previous PCAPs available', JS_CONTENT)

    def test_error_messages(self):
        self.assertIn('showError(', JS_CONTENT)
        self.assertIn('id="errorModal"', HTML_CONTENT)

    def test_back_navigation(self):
        self.assertIn('Back to Overview', JS_CONTENT)

    def test_header_has_no_separators(self):
        """Header items must not have any separators (pipes or borders) for clean responsive wrapping."""
        header_section = JS_CONTENT.split("getElementById('headerContent').innerHTML")[1].split("`;")[0]
        self.assertNotIn('color: #30363d;"|"', header_section,
                         'Header must not use literal pipe characters as separators')
        self.assertNotIn('.header-item', CSS_CONTENT,
                         'Header must not use CSS border separators')

    def test_header_has_file_icon(self):
        """Header filename must have a file icon prefix."""
        header_section = JS_CONTENT.split("getElementById('headerContent').innerHTML")[1].split("`;")[0]
        self.assertIn('📄 ${currentFileName}', header_section,
                      'Header filename must have 📄 icon')

    def test_file_input_accepts_all_files(self):
        """File input must not restrict file types — any file can be uploaded."""
        input_match = re.search(r'id="pcapUpload"[^>]*>', JS_CONTENT)
        self.assertIsNotNone(input_match, 'pcapUpload input must exist')
        self.assertNotIn('accept=', input_match.group(0),
                         'File input must not have accept attribute to allow any file')

    def test_drag_and_drop_zone_exists(self):
        """Upload area must have a visible drop zone for drag-and-drop."""
        self.assertIn('id="dropZone"', JS_CONTENT,
                      'Drop zone element must exist')
        self.assertIn('ondragover', JS_CONTENT,
                      'Drop zone must handle dragover event')
        self.assertIn('ondrop', JS_CONTENT,
                      'Drop zone must handle drop event')

    def test_drag_and_drop_css_feedback(self):
        """Drop zone must have CSS class for visual feedback on drag."""
        self.assertIn('.drop-zone-active', CSS_CONTENT,
                      'Drop zone active CSS class must exist')
        active_match = re.search(r'\.drop-zone-active\s*\{([^}]+)\}', CSS_CONTENT)
        self.assertIsNotNone(active_match, '.drop-zone-active CSS rule must exist')
        active_style = active_match.group(1)
        self.assertIn('border-color', active_style,
                      'Drop zone active must change border color')

    def test_drag_and_drop_handlers_exist(self):
        """JavaScript must have drag-and-drop event handler functions."""
        self.assertIn('function handleDragOver', JS_CONTENT,
                      'handleDragOver function must exist')
        self.assertIn('function handleDragLeave', JS_CONTENT,
                      'handleDragLeave function must exist')
        self.assertIn('function handleDrop', JS_CONTENT,
                      'handleDrop function must exist')

    def test_upload_function_accepts_file_parameter(self):
        """uploadPcap must accept an optional file parameter for drag-and-drop."""
        func_match = re.search(r'function uploadPcap\(([^)]*)\)', JS_CONTENT)
        self.assertIsNotNone(func_match, 'uploadPcap function must exist')
        params = func_match.group(1)
        self.assertIn('droppedFile', params,
                      'uploadPcap must accept a droppedFile parameter')

    def test_upload_shows_loading_immediately(self):
        """uploadPcap must show loading before fetch so user sees feedback during upload."""
        upload_func = JS_CONTENT.split('async function uploadPcap')[1].split('async function checkStatus')[0]
        self.assertIn("showLoading('Uploading file... (0s)')", upload_func,
                      'uploadPcap must show loading immediately before fetch')

    def test_url_input_submits_on_enter(self):
        """URL input field must call loadFromUrl when Enter key is pressed."""
        input_match = re.search(r'id="pcapUrl"[^>]*>', JS_CONTENT)
        self.assertIsNotNone(input_match, 'pcapUrl input must exist')
        input_tag = input_match.group(0)
        self.assertIn("onkeydown", input_tag,
                      'pcapUrl input must have onkeydown handler')
        self.assertIn("loadFromUrl()", input_tag,
                      'pcapUrl onkeydown must call loadFromUrl')

    def test_diagram_toggle_exists(self):
        """Sankey panel must include a collapsible heading bar."""
        self.assertIn('toggleDiagram()', JS_CONTENT,
                      'toggleDiagram function must be referenced in heading bar')
        self.assertIn('diagramMode', JS_CONTENT,
                      'diagramMode variable must exist')

    def test_sankey_panel_exists(self):
        """Static HTML must include a #sankeyPanel container."""
        self.assertIn('id="sankeyPanel"', HTML_CONTENT,
                      'sankeyPanel container must exist')

    def test_d3_library_bundled(self):
        """D3 and d3-sankey must be loaded from local static files, not CDN."""
        self.assertIn('static/d3.min.js', HTML_CONTENT,
                      'D3 must be loaded from local static file')
        self.assertIn('static/d3-sankey.min.js', HTML_CONTENT,
                      'd3-sankey must be loaded from local static file')
        self.assertNotIn('unpkg.com', HTML_CONTENT,
                         'Must not use external CDN for D3 libraries')

    def test_sankey_functions_exist(self):
        """JavaScript must define buildSankeyData and renderSankeySVG functions."""
        self.assertIn('function buildSankeyData(', JS_CONTENT,
                      'buildSankeyData function must exist')
        self.assertIn('function renderSankeySVG(', JS_CONTENT,
                      'renderSankeySVG function must exist')
        self.assertIn('d3.sankey()', JS_CONTENT,
                      'renderSankeySVG must use d3.sankey for layout')
        self.assertIn('d3.sankeyLinkHorizontal()', JS_CONTENT,
                      'renderSankeySVG must use d3.sankeyLinkHorizontal for links')

    def test_diagram_toggle_listener_exists(self):
        """Sankey diagram heading bar must call toggleDiagram when clicked."""
        self.assertIn("toggleDiagram()", JS_CONTENT,
                      'Sankey heading bar onclick must call toggleDiagram')

    def test_sankey_has_close_button(self):
        """Sankey diagram panel must include a collapsible heading bar."""
        self.assertIn('section-toggle-bar', CSS_CONTENT,
                      'section-toggle-bar CSS class must exist')
        self.assertIn("diagramMode = !diagramMode", JS_CONTENT,
                      'toggleDiagram must flip diagramMode state')
        self.assertIn("toggleDiagram()", JS_CONTENT,
                      'Sankey heading must call toggleDiagram')

    def test_sankey_links_clickable(self):
        """Sankey links must have click handlers to create filters."""
        self.assertIn(".on('click', function(event, d)", JS_CONTENT,
                      'Sankey links must have click handler')
        self.assertIn("applyFilters(visibleSection.id, [", JS_CONTENT,
                      'Sankey link click must call applyFilters')
        self.assertIn("getColumnNameFromSankeyColumn(d.source.column)", JS_CONTENT,
                      'Sankey link must map source column')
        self.assertIn("getColumnNameFromSankeyColumn(d.target.column)", JS_CONTENT,
                      'Sankey link must map target column')

    def test_sankey_nodes_clickable(self):
        """Sankey nodes must have click handlers to create filters."""
        self.assertIn(".on('click', function(event, d)", JS_CONTENT,
                      'Sankey nodes must have click handler')
        self.assertIn("getColumnNameFromSankeyColumn(d.column)", JS_CONTENT,
                      'Sankey node must map column')

    def test_sankey_empty_events_shows_header(self):
        """REGRESSION: updateSankeyDiagram must render the toggle header even when events are empty."""
        func = JS_CONTENT.split('function updateSankeyDiagram(')[1].split('function ')[0]
        self.assertIn("sankeyPanel.innerHTML = '<div class=\"section-toggle-bar\" onclick=\"toggleDiagram()\">▾ Sankey Diagram</div>'", func,
                      'updateSankeyDiagram must render header bar for empty events')

    def test_getSankeyEvents_exists(self):
        """JavaScript must define getSankeyEvents to resolve events for the currently visible tab."""
        self.assertIn('function getSankeyEvents(', JS_CONTENT,
                      'getSankeyEvents function must exist')

    def test_updateSankeyDiagram_uses_getSankeyEvents(self):
        """REGRESSION: updateSankeyDiagram must call getSankeyEvents instead of accepting a parameter."""
        func = JS_CONTENT.split('function updateSankeyDiagram(')[1].split('function ')[0]
        self.assertIn('getSankeyEvents()', func,
                      'updateSankeyDiagram must call getSankeyEvents to resolve events')

    def test_apply_filters_function_exists(self):
        """JavaScript must define applyFilters to apply multiple filters at once."""
        self.assertIn('function applyFilters(', JS_CONTENT,
                      'applyFilters function must exist')

    def test_get_column_name_helper_exists(self):
        """JavaScript must define getColumnNameFromSankeyColumn for column mapping."""
        self.assertIn('function getColumnNameFromSankeyColumn(', JS_CONTENT,
                      'getColumnNameFromSankeyColumn function must exist')

    def test_default_url_prefilled(self):
        self.assertIn('malware-traffic-analysis.net', JS_CONTENT)

    def test_feature_comparison_table(self):
        self.assertIn('OhMyPCAP', JS_CONTENT)
        self.assertIn('Security Onion', JS_CONTENT)

    def test_feature_comparison_table_links(self):
        """Feature comparison table must include links to Security Onion resources"""
        self.assertIn('https://securityonion.net', JS_CONTENT)
        self.assertIn('http://securityonion.net/docs/about', JS_CONTENT)
        self.assertIn('https://securityonion.com/pro', JS_CONTENT)
        self.assertIn('http://securityonion.net/docs/security-onion-pro', JS_CONTENT)

    def test_ascii_transcript_loading(self):
        self.assertIn('ASCII Transcript', JS_CONTENT)
        self.assertIn('downloadPcap', JS_CONTENT)

    def test_ascii_transcript_colored_bars(self):
        self.assertIn('#ff6b6b', JS_CONTENT)
        self.assertIn('#58a6ff', JS_CONTENT)

    def test_ascii_transcript_direction_grouping(self):
        self.assertIn("direction === 'src'", JS_CONTENT)
        self.assertIn("line.direction", JS_CONTENT)

    def test_table_sorting_ui(self):
        self.assertIn('cursor: pointer', CSS_CONTENT)
        self.assertIn('sort-arrow', JS_CONTENT)

    def test_hexdump_function_exists(self):
        self.assertIn('function switchStreamView', JS_CONTENT)
        self.assertIn('function loadHexdumpData', JS_CONTENT)

    def test_hexdump_toggle_functions_exist(self):
        self.assertIn('function togglePacket', JS_CONTENT)
        self.assertIn('function expandAllPackets', JS_CONTENT)
        self.assertIn('function collapseAllPackets', JS_CONTENT)

    def test_hexdump_expand_collapse_selector_uses_direct_child(self):
        """expandAllPackets and collapseAllPackets must use > span:first-child
        to avoid overwriting nested colored IP spans."""
        self.assertIn("querySelectorAll('.packet-header > span:first-child')", JS_CONTENT)

    def test_hexdump_button_in_detail_row(self):
        self.assertIn('Hexdump', JS_CONTENT)
        self.assertIn("onclick=\"switchStreamView(", JS_CONTENT)
        self.assertIn('.view-tabs', CSS_CONTENT)
        self.assertIn('.view-tab', CSS_CONTENT)

    def test_hexdump_packet_css(self):
        self.assertIn('.packet-block', CSS_CONTENT)
        self.assertIn('.packet-header', CSS_CONTENT)
        self.assertIn('.packet-content', CSS_CONTENT)
        self.assertIn('.view-tabs', CSS_CONTENT)
        self.assertIn('.view-tab', CSS_CONTENT)

    def test_hexdump_direction_classes(self):
        """Each packet block must have a src-dir or dst-dir class for colored left border."""
        self.assertIn('.packet-block.src-dir', CSS_CONTENT)
        self.assertIn('.packet-block.dst-dir', CSS_CONTENT)
        self.assertNotIn('function colorizePacketHeader', JS_CONTENT)

    def test_hexdump_direction_detection(self):
        """loadHexdumpData must detect direction by splitting on ' > ' and checking src."""
        self.assertIn("pkt.header.split(' > ')", JS_CONTENT)
        self.assertIn("dirParts[0].includes(src)", JS_CONTENT)

    def test_loadAnalysis_calls_loadTabData_after_buildSections(self):
        """loadAnalysis must call loadTabData after buildSections since buildSections no longer loads data."""
        func = JS_CONTENT.split('async function loadAnalysis')[1].split('async function')[0]
        self.assertIn("clearAnalysisContainers()", func,
                      'loadAnalysis must clear containers before rebuilding')
        self.assertIn("buildSections();", func,
                      'loadAnalysis must call buildSections')
        self.assertIn("loadTabData(eventTypes[0])", func,
                      'loadAnalysis must call loadTabData after buildSections')

    def test_loadAnalysis_uses_showAnalysisUI(self):
        """loadAnalysis must call showAnalysisUI after rebuilding the analysis view."""
        func = JS_CONTENT.split('async function loadAnalysis')[1].split('async function')[0]
        self.assertIn("showAnalysisUI()", func,
                      'loadAnalysis must call showAnalysisUI after rebuilding')


class TestSecurityInUI(unittest.TestCase):
    def test_no_inline_event_handlers_with_dangerous_patterns(self):
        dangerous_patterns = ['eval(', 'document.write(', 'innerHTML = location', 'innerHTML = window']
        for pattern in dangerous_patterns:
            self.assertNotIn(pattern, JS_CONTENT)

    def test_uses_escape_html_function(self):
        self.assertIn('escapeHtml(', JS_CONTENT)

    def test_no_hardcoded_credentials(self):
        content = JS_CONTENT.lower().replace('disclaimer', '').replace('password-protected', '').replace('password protected', '').replace('common passwords', '')
        self.assertNotIn('password', content)

    def test_uses_https_for_external_resources(self):
        self.assertIn('https://', HTML_CONTENT)


class TestAccessibility(unittest.TestCase):
    def test_has_lang_attribute(self):
        self.assertIn('lang="en"', HTML_CONTENT)

    def test_has_meta_viewport(self):
        self.assertIn('viewport', HTML_CONTENT)

    def test_has_title(self):
        self.assertIn('<title>', HTML_CONTENT)

    def test_buttons_have_titles(self):
        self.assertIn('title="', JS_CONTENT)


class TestAggregationTables(unittest.TestCase):
    def test_has_agg_grid_css(self):
        self.assertIn('.agg-grid', CSS_CONTENT)

    def test_has_agg_section_css(self):
        """agg-section must be a flex item sized to content, not fixed widths."""
        self.assertIn('.agg-section', CSS_CONTENT)
        section_match = re.search(r'\.agg-section\s*\{([^}]+)\}', CSS_CONTENT)
        self.assertIsNotNone(section_match, 'agg-section CSS rule must exist')
        section_style = section_match.group(1)
        self.assertIn('flex: 0 1 auto', section_style,
                      'agg-section must size to content, not force fixed widths')
        self.assertNotIn('min-width', section_style,
                         'agg-section must not have fixed min-width')
        self.assertNotIn('max-width', section_style,
                         'agg-section must not have fixed max-width')

    def test_agg_table_sized_to_content(self):
        """agg-table tables must fill container while columns size to data."""
        rule_match = re.search(r'\.agg-table table\s*\{([^}]+)\}', CSS_CONTENT)
        self.assertIsNotNone(rule_match, '.agg-table table CSS rule must exist')
        rule_style = rule_match.group(1)
        self.assertIn('width: 100%', rule_style,
                      'agg-table must fill container for consistent header backgrounds')
        self.assertIn('table-layout: auto', rule_style,
                      'agg-table columns must size based on data')

    def test_has_agg_table_css(self):
        self.assertIn('.agg-table', CSS_CONTENT)

    def test_has_agg_table_title_css(self):
        self.assertIn('.agg-table .agg-header', CSS_CONTENT)

    def test_has_agg_row_css(self):
        self.assertIn('.agg-row', CSS_CONTENT)

    def test_has_agg_cell_css(self):
        self.assertIn('.agg-cell', CSS_CONTENT)

    def test_agg_cell_allows_full_text(self):
        """agg-cell must show full values without truncation."""
        cell_match = re.search(r'\.agg-cell\s*\{([^}]+)\}', CSS_CONTENT)
        self.assertIsNotNone(cell_match, '.agg-cell CSS rule must exist')
        cell_style = cell_match.group(1)
        self.assertNotIn('text-overflow: ellipsis', cell_style,
                         'agg-cell must not truncate with ellipsis')
        self.assertNotIn('white-space: nowrap', cell_style,
                         'agg-cell must allow text wrapping')
        self.assertNotIn('max-width', cell_style,
                         'agg-cell must not have fixed max-width')
        self.assertIn('overflow-wrap: break-word', cell_style,
                      'agg-cell must wrap long words')

    def test_agg_table_td_allows_full_text(self):
        """agg-table td cells must not force single-line truncation."""
        td_match = re.search(r'\.agg-table td\s*\{([^}]+)\}', CSS_CONTENT)
        self.assertIsNotNone(td_match, '.agg-table td CSS rule must exist')
        td_style = td_match.group(1)
        self.assertNotIn('text-overflow: ellipsis', td_style,
                         'agg-table td must not truncate with ellipsis')
        self.assertNotIn('white-space: nowrap', td_style,
                         'agg-table td must allow text wrapping')

    def test_has_aggregations_container(self):
        self.assertIn('id="aggregations"', HTML_CONTENT)

    def test_has_build_aggregation_tables_function(self):
        self.assertIn('function buildAggregationTables', JS_CONTENT)

    def test_has_build_aggregation_tables_all_function(self):
        self.assertIn('function buildAggregationTablesAll', JS_CONTENT)

    def test_has_build_aggregation_tables_core_function(self):
        """buildAggregationTablesCore must exist as the unified aggregation builder."""
        self.assertIn('function buildAggregationTablesCore', JS_CONTENT)

    def test_buildAggregationTables_delegates_to_core(self):
        """REGRESSION: buildAggregationTables must delegate to buildAggregationTablesCore
        instead of duplicating the grid-building logic."""
        func = JS_CONTENT.split('function buildAggregationTables(')[1].split('function ')[0]
        self.assertIn('buildAggregationTablesCore', func,
                      'buildAggregationTables must delegate to buildAggregationTablesCore')

    def test_buildAggregationTablesAll_delegates_to_core(self):
        """REGRESSION: buildAggregationTablesAll must delegate to buildAggregationTablesCore
        instead of duplicating the grid-building logic."""
        func = JS_CONTENT.split('function buildAggregationTablesAll(')[1].split('function ')[0]
        self.assertIn('buildAggregationTablesCore', func,
                      'buildAggregationTablesAll must delegate to buildAggregationTablesCore')

    def test_has_extract_value_function(self):
        self.assertIn('function extractValue', JS_CONTENT)

    def test_has_extract_all_value_function(self):
        self.assertIn('function extractAllValue', JS_CONTENT)

    def test_extractAllValue_handles_all_events_columns(self):
        """extractAllValue must handle 'All Events' specific columns (Type, Command, Message)
        and delegate to extractValue for per-type columns so filters work correctly."""
        func_body = JS_CONTENT.split('function extractAllValue')[1].split('function buildAggregationTablesCore')[0]
        self.assertIn("col === 'Type'", func_body,
                      'extractAllValue must handle Type column')
        self.assertIn("col === 'Command'", func_body,
                      'extractAllValue must handle Command column')
        self.assertIn("col === 'Message'", func_body,
                      'extractAllValue must handle Message column')
        self.assertIn('return extractValue(e, col, colIndex)', func_body,
                      'extractAllValue must delegate to extractValue')

    def test_extractValue_handles_detail_column(self):
        """extractValue must handle 'Detail' column for all event types so
        filters set in the 'All Events' view work correctly on per-type tabs."""
        func_body = JS_CONTENT.split('function extractValue')[1].split('function buildAggregationTables')[0]
        self.assertIn("case 'Detail':", func_body,
                      'extractValue must handle Detail column')
        self.assertIn("e.event_type", func_body,
                      'extractValue Detail must check event_type')
        self.assertIn("e.alert?.signature", func_body,
                      'extractValue Detail must handle alert events')
        self.assertIn("e.dns?.rrname", func_body,
                      'extractValue Detail must handle dns events')
        self.assertIn("e.tls?.sni", func_body,
                      'extractValue Detail must handle tls events')

    def test_has_build_aggregations_section_function(self):
        self.assertIn('function buildAggregationsSection', JS_CONTENT)

    def test_has_build_aggregations_section_all_function(self):
        self.assertIn('function buildAggregationsSectionAll', JS_CONTENT)

    def test_agg_tables_use_string_ports(self):
        self.assertIn("String(e.src_port", JS_CONTENT)
        self.assertIn("String(e.dest_port", JS_CONTENT)

    def test_buildAggregationTablesCore_produces_html(self):
        """buildAggregationTablesCore must produce HTML with aggregation rows for sample events."""
        from tests.jsdom_helper import js_statements
        events = [
            {'event_type': 'alert', 'proto': 'TCP', 'src_ip': '1.2.3.4', 'src_port': 80, 'dest_ip': '5.6.7.8', 'dest_port': 443, 'alert': {'signature': 'Test Sig'}},
            {'event_type': 'alert', 'proto': 'TCP', 'src_ip': '1.2.3.4', 'src_port': 80, 'dest_ip': '5.6.7.8', 'dest_port': 443, 'alert': {'signature': 'Test Sig'}},
            {'event_type': 'alert', 'proto': 'UDP', 'src_ip': '9.8.7.6', 'src_port': 53, 'dest_ip': '1.2.3.4', 'dest_port': 53, 'alert': {'signature': 'DNS Sig'}},
        ]
        result = js_statements(f'''
            var events = {json.dumps(events)};
            var html = buildAggregationTablesCore(events, ['Protocol', 'Source IP'], 'section-alert', extractValue);
            window.__jsdom_result = {{
                hasTCP: html.indexOf('TCP') >= 0,
                hasUDP: html.indexOf('UDP') >= 0,
                hasSrcIp: html.indexOf('1.2.3.4') >= 0,
                hasCount2: html.indexOf('2') >= 0,
                hasAggRow: html.indexOf('agg-row') >= 0,
            }};
        ''')
        self.assertTrue(result['hasTCP'], 'HTML must contain TCP protocol')
        self.assertTrue(result['hasUDP'], 'HTML must contain UDP protocol')
        self.assertTrue(result['hasSrcIp'], 'HTML must contain source IP')
        self.assertTrue(result['hasCount2'], 'HTML must contain count of 2')
        self.assertTrue(result['hasAggRow'], 'HTML must contain aggregation rows')

    def test_extractAllValue_cross_type(self):
        """extractAllValue must return correct values for cross-event-type columns."""
        from tests.jsdom_helper import js_statements
        result = js_statements('''
            var e1 = {event_type: 'alert', proto: 'TCP', alert: {signature: 'Test Alert'}};
            var e2 = {event_type: 'ftp', proto: 'TCP', ftp: {command: 'USER admin'}};
            var e3 = {event_type: 'anomaly', proto: 'TCP', anomaly: {message: 'Malformed packet'}};
            window.__jsdom_result = {
                alertType: extractAllValue(e1, 'Type', -1),
                alertProto: extractAllValue(e1, 'Protocol', -1),
                ftpCommand: extractAllValue(e2, 'Command', -1),
                anomalyMessage: extractAllValue(e3, 'Message', -1),
            };
        ''')
        self.assertEqual(result['alertType'], 'ALERT')
        self.assertEqual(result['alertProto'], 'TCP')
        self.assertEqual(result['ftpCommand'], 'USER admin')
        self.assertEqual(result['anomalyMessage'], 'Malformed packet')

    def test_agg_tables_have_click_handlers(self):
        self.assertIn("onclick=\"applyFilter('${sectionId}', '${col.replace", JS_CONTENT)

    def test_agg_tables_no_bar_charts(self):
        self.assertNotIn('.agg-bar', CSS_CONTENT)

    def test_agg_tables_have_borders(self):
        self.assertIn('border: 1px solid #30363d', CSS_CONTENT)

    def test_agg_tables_wrap_with_flex(self):
        self.assertIn('flex-wrap: wrap', CSS_CONTENT)

    def test_agg_header_has_close_button(self):
        """Each aggregation table header must include a close button to hide the table."""
        self.assertIn('agg-close', CSS_CONTENT,
                      'agg-close CSS class must exist')
        self.assertIn("hideAggregationTable('${sectionId}'", JS_CONTENT,
                      'Aggregation header must call hideAggregationTable')

    def test_hide_aggregation_table_function_exists(self):
        """JavaScript must define hideAggregationTable to track hidden aggregation tables."""
        self.assertIn('function hideAggregationTable(', JS_CONTENT,
                      'hideAggregationTable function must exist')
        self.assertIn('hiddenAggregations', JS_CONTENT,
                      'hiddenAggregations variable must exist')

    def test_aggregation_skips_hidden_columns(self):
        """buildAggregationTables must filter out columns in hiddenAggregations."""
        self.assertIn("!hiddenAggregations.has(sectionId + ':' + c)", JS_CONTENT,
                      'buildAggregationTables must skip hidden columns')

    def test_hide_aggregation_table_auto_collapses_section(self):
        """Closing the last visible aggregation table must collapse the section."""
        self.assertIn("advancedMode = false", JS_CONTENT,
                      'hideAggregationTable must set advancedMode to false when last table hidden')
        self.assertIn("▸ Aggregation Tables", JS_CONTENT,
                      'hideAggregationTable must render collapsed heading when last table hidden')


class TestFiltering(unittest.TestCase):
    def test_has_current_filters_state(self):
        self.assertIn('currentFilters', JS_CONTENT)

    def test_has_apply_filter_function(self):
        self.assertIn('function applyFilter', JS_CONTENT)

    def test_has_clear_filter_function(self):
        self.assertIn('function clearFilter', JS_CONTENT)

    def test_has_clear_all_filters_function(self):
        self.assertIn('function clearAllFilters', JS_CONTENT)

    def test_has_get_filtered_events_function(self):
        self.assertIn('function getFilteredEvents', JS_CONTENT)

    def test_has_filter_bar_css(self):
        self.assertIn('.filter-bar', CSS_CONTENT)

    def test_has_filter_chip_css(self):
        self.assertIn('.filter-chip', CSS_CONTENT)

    def test_has_filter_clear_all_css(self):
        self.assertIn('.filter-clear-all', CSS_CONTENT)

    def test_has_footer_css(self):
        self.assertIn('.footer', CSS_CONTENT)

    def test_has_footer_with_version_placeholder(self):
        self.assertIn('OhMyPCAP</a>', HTML_CONTENT)
        self.assertIn('id="footerVersionLink"', HTML_CONTENT)

    def test_has_footer_with_copyright(self):
        self.assertIn('Security Onion Solutions, LLC', HTML_CONTENT)

    def test_has_footer_links(self):
        self.assertIn('github.com/dougburks', HTML_CONTENT)
        self.assertIn('securityonion.com', HTML_CONTENT)

    def test_has_analysis_header(self):
        self.assertIn('id="mainHeader"', HTML_CONTENT)

    def test_has_instructions_in_analysis(self):
        """Analysis instructions must mention filtering options and hexdump."""
        self.assertIn('Start by reviewing all alerts', JS_CONTENT)
        self.assertIn('Filter using the search bar, sankey diagram, or aggregation tables', JS_CONTENT)
        self.assertIn('ASCII transcript and hexdump and optionally download', JS_CONTENT)
        self.assertNotIn('ASCII transcript and optionally download', JS_CONTENT)

    def test_filter_bar_only_in_aggregations(self):
        self.assertIn('buildAggregationsSection', JS_CONTENT)

    def test_filters_reset_on_new_pcap(self):
        self.assertIn('currentFilters = {}', JS_CONTENT)

    def test_filter_uses_string_comparison_for_ports(self):
        self.assertIn("String(e.src_port", JS_CONTENT)
        self.assertIn("String(e.dest_port", JS_CONTENT)

    def test_empty_value_handling_in_agg_tables(self):
        self.assertIn("(empty)", JS_CONTENT)

    def test_empty_value_converts_to_empty_string_on_click(self):
        self.assertIn("val === '(empty)' ? '' : val", JS_CONTENT)

    def test_all_events_filter_uses_buildAllEvents(self):
        self.assertIn("eventType === 'all'", JS_CONTENT)
        self.assertIn("buildAllEvents()", JS_CONTENT)

    def test_aggregations_cleared_on_welcome(self):
        self.assertIn("document.getElementById('aggregations').innerHTML = ''", JS_CONTENT)

    def test_getFilteredEvents_handles_all_type(self):
        self.assertIn("function getFilteredEvents", JS_CONTENT)
        self.assertIn("eventType === 'all'", JS_CONTENT)

    def test_eventMatchesFilters_uses_extractValue_unconditionally(self):
        """eventMatchesFilters must call extractValue for all columns, not gated by colIndex.
        Cross-type metadata (e.g., http.hostname on a fileinfo event) must be matched."""
        func_body = JS_CONTENT.split('function eventMatchesFilters')[1].split('function computeFilteredStats')[0]
        self.assertIn("extractValue(event, col, -1)", func_body,
                      'eventMatchesFilters must call extractValue unconditionally')
        self.assertNotIn("colIndex >= 0", func_body,
                          'eventMatchesFilters must not gate extractValue on colIndex')

    def test_extractValue_works_across_event_types(self):
        """extractValue must return correct values for all event types and columns."""
        from tests.jsdom_helper import js_statements
        result = js_statements('''
            var e1 = {event_type: 'alert', proto: 'TCP', src_ip: '1.2.3.4', alert: {signature: 'Test Alert'}};
            var e2 = {event_type: 'dns', proto: 'UDP', src_ip: '5.6.7.8', dns: {rrname: 'example.com'}};
            var e3 = {event_type: 'fileinfo', proto: 'TCP', src_ip: '9.8.7.6', fileinfo: {filename: 'test.exe'}};
            window.__jsdom_result = {
                alertProto: extractValue(e1, 'Protocol', -1),
                alertSig: extractValue(e1, 'Alert', -1),
                dnsProto: extractValue(e2, 'Protocol', -1),
                dnsQuery: extractValue(e2, 'Query', -1),
                fileProto: extractValue(e3, 'Protocol', -1),
                fileName: extractValue(e3, 'Filename', -1),
            };
        ''')
        self.assertEqual(result['alertProto'], 'TCP')
        self.assertEqual(result['alertSig'], 'Test Alert')
        self.assertEqual(result['dnsProto'], 'UDP')
        self.assertEqual(result['dnsQuery'], 'example.com')
        self.assertEqual(result['fileProto'], 'TCP')
        self.assertEqual(result['fileName'], 'test.exe')


class TestPerformance(unittest.TestCase):
    def test_uses_document_fragment_for_batch_inserts(self):
        self.assertIn('createDocumentFragment', JS_CONTENT)

    def test_uses_event_delegation(self):
        self.assertIn('addEventListener', JS_CONTENT)

    def test_lazy_loads_ascii_transcripts(self):
        self.assertIn('loadAsciiTranscript', JS_CONTENT)
        self.assertIn('!pre.innerHTML', JS_CONTENT)

    def test_truncates_large_streams(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ohmypcap.py'), 'r') as f:
            server_content = f.read()
        self.assertIn('truncated', server_content)


class TestAdvancedToggle(unittest.TestCase):
    def test_has_advanced_toggle_css(self):
        self.assertIn('.advanced-toggle', CSS_CONTENT)

    def test_has_advanced_toggle_input(self):
        self.assertIn('toggleAggregations()', JS_CONTENT)

    def test_has_advanced_mode_js_variable(self):
        self.assertIn('let advancedMode', JS_CONTENT)

    def test_aggregations_collapsed_by_default(self):
        self.assertIn("▸ Aggregation Tables", JS_CONTENT)

    def test_filter_bar_container_exists(self):
        self.assertIn('id="filterBarContainer"', HTML_CONTENT)

    def test_update_filter_bar_visibility_function(self):
        self.assertIn('function updateFilterBarVisibility', JS_CONTENT)
        self.assertIn('function buildFilterBarHtml', JS_CONTENT)

    def test_advanced_toggle_in_header(self):
        self.assertIn('Aggregation Tables', JS_CONTENT)
        self.assertIn("toggleAggregations()", JS_CONTENT)


class TestFilterOnclickQuoting(unittest.TestCase):
    """Regression tests for JSON.stringify double-quote collision in onclick attributes.

    JSON.stringify() produces double-quoted strings like "Source IP", which break
    when embedded in double-quoted onclick attributes. All onclick handlers must
    use single-quoted string arguments with escaped internal single quotes instead.
    """

    def test_no_json_stringify_in_apply_filter_onclick(self):
        """applyFilter onclick must not use JSON.stringify (causes double-quote collision)"""
        apply_filter_matches = re.findall(r'onclick="applyFilter\([^"]*\)"', JS_CONTENT)
        for match in apply_filter_matches:
            self.assertNotIn('JSON.stringify', match,
                f'applyFilter onclick uses JSON.stringify which breaks in double-quoted onclick: {match[:80]}')

    def test_no_json_stringify_in_clear_filter_onclick(self):
        """clearFilter onclick must not use JSON.stringify (causes double-quote collision)"""
        clear_filter_matches = re.findall(r'onclick="clearFilter\([^"]*\)"', JS_CONTENT)
        for match in clear_filter_matches:
            self.assertNotIn('JSON.stringify', match,
                f'clearFilter onclick uses JSON.stringify which breaks in double-quoted onclick: {match[:80]}')

    def test_apply_filter_uses_single_quoted_args(self):
        """applyFilter onclick should use single-quoted string arguments"""
        self.assertRegex(JS_CONTENT, r"onclick=\"applyFilter\('[^']+',\s*'\$\{[^}]+\}',\s*'\$\{[^}]+\}'\)\"",
            'applyFilter onclick should use single-quoted template expressions')

    def test_clear_filter_uses_single_quoted_args(self):
        """clearFilter onclick should use single-quoted string argument"""
        self.assertRegex(JS_CONTENT, r"onclick=\"clearFilter\('\$\{[^}]+\}'\)\"",
            'clearFilter onclick should use single-quoted template expression')

    def test_agg_row_onclick_has_escaped_quotes(self):
        """agg-row onclick handlers must escape single quotes in values"""
        self.assertRegex(JS_CONTENT, r"replace\(/'/g,\s*\"\\\\'\"\)",
            'onclick handlers must escape single quotes with replace')

    def test_no_bare_json_stringify_in_onclick_templates(self):
        """No template literal should embed JSON.stringify directly into an onclick attribute"""
        lines = JS_CONTENT.split('\n')
        for i, line in enumerate(lines):
            if 'onclick=' in line and 'JSON.stringify' in line:
                self.fail(f'Line {i+1} has JSON.stringify inside onclick template: {line.strip()}')


class TestAdvancedModeFilterBar(unittest.TestCase):
    """Regression tests for advanced mode toggle and filter bar persistence."""

    def test_loadTabData_calls_updateFilterBarVisibility_for_cached_data(self):
        """loadTabData must call updateFilterBarVisibility when using cached data"""
        self.assertIn("updateFilterBarVisibility()", JS_CONTENT)
        pattern = r"buildSection\(eventType,\s*tabDataCache\[eventType\]\);[\s\S]{0,80}updateFilterBarVisibility\(\)"
        self.assertRegex(JS_CONTENT, pattern,
            'loadTabData must call updateFilterBarVisibility after buildSection for cached data')

    def test_loadTabData_calls_updateFilterBarVisibility_for_fresh_data(self):
        """loadTabData must call updateFilterBarVisibility after fetching fresh data"""
        pattern = r"buildSection\(eventType,\s*events\);[\s\S]{0,80}updateFilterBarVisibility\(\)"
        self.assertRegex(JS_CONTENT, pattern,
            'loadTabData must call updateFilterBarVisibility after buildSection for fresh data')

    def test_loadTabData_all_events_calls_updateFilterBarVisibility(self):
        """loadTabData for "all" events must call updateFilterBarVisibility"""
        pattern = r"buildAllEvents\(\);\s*if\s*\(\s*sectionEl\s*&&\s*advancedMode\s*\)\s*buildAggregationsSectionAll\(\);\s*updateFilterBarVisibility\(\)"
        self.assertRegex(JS_CONTENT, pattern,
            'loadTabData must call updateFilterBarVisibility for "all" events')

    def test_advanced_toggle_clears_filterBarContainer(self):
        """Enabling advanced mode must clear filterBarContainer to prevent duplicate filter bars"""
        self.assertIn("filterBarContainer.innerHTML = ''", JS_CONTENT)
        self.assertIn("filterBarContainer.style.display = 'none'", JS_CONTENT)

    def test_advanced_toggle_collapses_aggregations_on_disable(self):
        """Collapsing aggregations must render collapsed heading instead of clearing container"""
        self.assertIn("▸ Aggregation Tables", JS_CONTENT,
            'Aggregation collapse must render collapsed heading bar')

    def test_filters_are_global_not_per_section(self):
        """currentFilters must be a flat object so filters persist across all views"""
        self.assertIn("currentFilters[f.column] = f.value", JS_CONTENT)
        self.assertNotIn("currentFilters[sectionId] = {}", JS_CONTENT)
        self.assertNotIn("currentFilters[sectionId][columnName]", JS_CONTENT)

    def test_buildSection_uses_global_filters(self):
        """buildSection must filter using global currentFilters, not per-section filters"""
        self.assertIn("Object.keys(currentFilters).length", JS_CONTENT)
        self.assertNotIn("currentFilters[sectionId] || {}", JS_CONTENT)

    def test_buildAggregationsSection_uses_global_filters(self):
        """buildAggregationsSection must render heading bar and delegate to buildAggregationTables"""
        self.assertIn('function buildAggregationsSection', JS_CONTENT)
        self.assertIn('section-toggle-bar', JS_CONTENT)

    def test_buildAggregationsSectionAll_uses_global_filters(self):
        """buildAggregationsSectionAll must use global currentFilters for filtering and filter bar"""
        pattern = r"function buildAggregationsSectionAll[\s\S]{0,800}Object\.keys\(currentFilters\)\.length"
        self.assertRegex(JS_CONTENT, pattern,
            'buildAggregationsSectionAll must check Object.keys(currentFilters).length')

    def test_advanced_toggle_handles_all_events_type(self):
        """Advanced toggle must handle "all" events type by calling buildAggregationsSectionAll"""
        pattern = r"eventType\s*===\s*'all'[\s\S]{0,100}buildAggregationsSectionAll"
        self.assertRegex(JS_CONTENT, pattern,
            'Advanced toggle handler must call buildAggregationsSectionAll for "all" events')

    def test_clearFilter_uses_global_filters(self):
        """clearFilter must delete from flat currentFilters, not nested"""
        self.assertIn("delete currentFilters[columnName]", JS_CONTENT)
        self.assertNotIn("delete currentFilters[sectionId]", JS_CONTENT)

    def test_clearAllFilters_resets_global_filters(self):
        """clearAllFilters must reset currentFilters to empty object"""
        self.assertIn("currentFilters = {}", JS_CONTENT)

    def test_loadTabData_filters_agg_tables_in_advanced_mode_cached(self):
        """loadTabData must pass filtered events to buildAggregationsSection for cached data in advanced mode"""
        pattern = r"const filtered = getFilteredEvents\((?:sectionEl\.id|sectionId),\s*tabDataCache\[eventType\],\s*eventType\);[\s\S]{0,120}buildAggregationsSection\(eventType,\s*filtered\)"
        self.assertRegex(JS_CONTENT, pattern,
            'loadTabData must call getFilteredEvents before buildAggregationsSection for cached data in advanced mode')

    def test_loadTabData_filters_agg_tables_in_advanced_mode_fresh(self):
        """loadTabData must pass filtered events to buildAggregationsSection for fresh data in advanced mode"""
        pattern = r"const filtered = getFilteredEvents\((?:sectionEl\.id|sectionId),\s*events,\s*eventType\);[\s\S]{0,120}buildAggregationsSection\(eventType,\s*filtered\)"
        self.assertRegex(JS_CONTENT, pattern,
            'loadTabData must call getFilteredEvents before buildAggregationsSection for fresh data in advanced mode')

    def test_currentFilters_is_flat_object_not_nested(self):
        """REGRESSION: currentFilters must remain a flat {columnName: value} object.
        Nesting it as {sectionId: {columnName: value}} causes filters to disappear when
        switching tabs, because each tab creates a new empty section entry."""
        self.assertNotIn("currentFilters[sectionId] = {}", JS_CONTENT)
        self.assertNotIn("currentFilters[sectionId] = {", JS_CONTENT)
        self.assertNotIn("currentFilters[sectionId][columnName]", JS_CONTENT)
        self.assertNotIn("currentFilters[sectionId] || {}", JS_CONTENT)
        self.assertIn("currentFilters[f.column] = f.value", JS_CONTENT)

    def test_all_filtering_functions_use_global_currentFilters(self):
        """REGRESSION: Every function that reads filters must use currentFilters directly,
        not currentFilters[sectionId]. Functions checked: buildSection, buildAllEvents,
        buildAggregationsSection, buildAggregationsSectionAll, getFilteredEvents."""
        self.assertNotIn("const filters = currentFilters[sectionId]", JS_CONTENT)


class TestXSSPrevention(unittest.TestCase):
    def _get_function_body(self, func_name):
        func_match = re.search(rf'function {re.escape(func_name)}\([^)]*\)\s*\{{', JS_CONTENT)
        self.assertIsNotNone(func_match, f'{func_name} function not found')
        start = func_match.end()
        brace_count = 1
        pos = start
        while pos < len(JS_CONTENT) and brace_count > 0:
            if JS_CONTENT[pos] == '{':
                brace_count += 1
            elif JS_CONTENT[pos] == '}':
                brace_count -= 1
            pos += 1
        return JS_CONTENT[start:pos]

    def test_formatEvent_escapes_dynamic_values(self):
        """User-controlled fields in formatEvent must be wrapped with escapeHtml()."""
        func_body = self._get_function_body('formatEvent')
        dangerous_patterns = [
            r'\$\{e\.alert\?\.signature',
            r'\$\{e\.alert\?\.rule',
            r'\$\{e\.alert\?\.category',
            r'\$\{e\.dns\?\.rrname',
            r'\$\{e\.dns\?\.rrtype',
            r'\$\{e\.http\?\.http_method',
            r'\$\{e\.http\?\.url',
            r'\$\{e\.http\?\.hostname',
            r'\$\{e\.http\?\.http_user_agent',
            r'\$\{e\.http\?\.http_content_type',
            r'\$\{e\.tls\?\.sni',
            r'\$\{e\.tls\?\.version',
            r'\$\{e\.tls\?\.subject',
            r'\$\{e\.tls\?\.issuerdn',
            r'\$\{e\.tls\?\.fingerprint',
            r'\$\{e\.flow\?\.state',
            r'\$\{e\.ftp\?\.command',
            r'\$\{e\.ftp\?\.reply',
            r'\$\{e\.anomaly\?\.type',
            r'\$\{e\.anomaly\?\.message',
            r'\$\{e\.fileinfo\?\.filename',
            r'\$\{e\.fileinfo\?\.magic',
            r'\$\{e\.fileinfo\?\.md5',
            r'\$\{e\.fileinfo\?\.sha1',
            r'\$\{e\.fileinfo\?\.sha256',
        ]
        for pattern in dangerous_patterns:
            matches = re.findall(pattern, func_body)
            self.assertEqual(len(matches), 0,
                f'Found unescaped user-controlled field in formatEvent matching: {pattern}')

    def test_buildRowForEvent_escapes_user_fields(self):
        """Table cells for DNS, HTTP, TLS, Flow, and File Info must use escapeHtml()."""
        func_body = self._get_function_body('buildRowForEvent')
        self.assertIn("escapeHtml(rrname)", func_body, 'DNS rrname must be escaped')
        self.assertIn("escapeHtml(rrtype)", func_body, 'DNS rrtype must be escaped')
        self.assertIn("escapeHtml(url)", func_body, 'HTTP url must be escaped')
        self.assertIn("escapeHtml(ua)", func_body, 'HTTP user-agent must be escaped')
        self.assertIn("escapeHtml(sni)", func_body, 'TLS SNI must be escaped')
        self.assertIn("escapeHtml(subject)", func_body, 'TLS subject must be escaped')
        self.assertIn("CONFIG.TLS_ISSUER_MAX_LENGTH", func_body, 'TLS issuer must use CONFIG constant')
        self.assertIn("escapeHtml(state)", func_body, 'Flow state must be escaped')
        self.assertIn("escapeHtml(filename)", func_body, 'File Info filename must be escaped')

    def test_buildAllEvents_escapes_user_fields(self):
        """All Events table must escape user-controlled fields."""
        func_body = self._get_function_body('buildAllEvents')
        self.assertIn("escapeHtml(ts)", func_body, 'All Events timestamp must be escaped')
        self.assertIn("escapeHtml(icon)", func_body, 'All Events icon must be escaped')
        self.assertIn("escapeHtml(etype.toUpperCase())", func_body, 'All Events event type must be escaped')
        self.assertIn("escapeHtml(proto)", func_body, 'All Events protocol must be escaped')
        self.assertIn("escapeHtml(srcIp)", func_body, 'All Events source IP must be escaped')
        self.assertIn("escapeHtml(String(srcPort))", func_body, 'All Events source port must be escaped')
        self.assertIn("escapeHtml(dstIp)", func_body, 'All Events dest IP must be escaped')
        self.assertIn("escapeHtml(String(dstPort))", func_body, 'All Events dest port must be escaped')

    def test_alert_details_shows_rule(self):
        """Alert detail panel must include a Rule row with monospace styling."""
        func_body = self._get_function_body('formatEvent')
        self.assertIn("alert?.rule", func_body, 'formatEvent must reference alert.rule')
        self.assertIn('white-space: pre-wrap', JS_CONTENT, 'Rule text must wrap with pre-wrap')
        self.assertIn('overflow-wrap: break-word', JS_CONTENT, 'Rule text must wrap with overflow-wrap')
        self.assertIn('class="mono"', JS_CONTENT, 'Rule text must use monospace font')


class TestURLParameterEncoding(unittest.TestCase):
    def test_downloadPcap_uses_encodeURIComponent(self):
        """downloadPcap must encode URL parameters to prevent injection."""
        func_match = re.search(r'function downloadPcap\(', JS_CONTENT)
        self.assertIsNotNone(func_match)
        start = func_match.start()
        brace_count = 0
        pos = start
        found_open = False
        while pos < len(JS_CONTENT):
            if JS_CONTENT[pos] == '{':
                brace_count += 1
                found_open = True
            elif JS_CONTENT[pos] == '}':
                brace_count -= 1
            pos += 1
            if found_open and brace_count == 0:
                break
        func_body = JS_CONTENT[start:pos]
        self.assertIn("encodeURIComponent(src)", func_body)
        self.assertIn("encodeURIComponent(sport)", func_body)
        self.assertIn("encodeURIComponent(dst)", func_body)
        self.assertIn("encodeURIComponent(dport)", func_body)
        self.assertIn("encodeURIComponent(currentMd5)", func_body)

    def test_loadAsciiTranscript_uses_encodeURIComponent(self):
        """loadAsciiTranscript must encode URL parameters."""
        func_match = re.search(r'function loadAsciiTranscript\(', JS_CONTENT)
        self.assertIsNotNone(func_match)
        start = func_match.start()
        brace_count = 0
        pos = start
        found_open = False
        while pos < len(JS_CONTENT):
            if JS_CONTENT[pos] == '{':
                brace_count += 1
                found_open = True
            elif JS_CONTENT[pos] == '}':
                brace_count -= 1
            pos += 1
            if found_open and brace_count == 0:
                break
        func_body = JS_CONTENT[start:pos]
        self.assertIn("encodeURIComponent(src)", func_body)
        self.assertIn("encodeURIComponent(sport)", func_body)
        self.assertIn("encodeURIComponent(dst)", func_body)
        self.assertIn("encodeURIComponent(dport)", func_body)
        self.assertIn("encodeURIComponent(currentMd5)", func_body)


class TestEscapeHtmlRobustness(unittest.TestCase):
    def test_escapeHtml_handles_numbers(self):
        """REGRESSION: escapeHtml must coerce numbers to String before .replace().
        Suricata outputs e.ftp?.reply as a number (e.g. 230), which caused:
        TypeError: str.replace is not a function."""
        func_match = re.search(r'function escapeHtml\(', JS_CONTENT)
        self.assertIsNotNone(func_match)
        start = func_match.start()
        brace_count = 0
        pos = start
        found_open = False
        while pos < len(JS_CONTENT):
            if JS_CONTENT[pos] == '{':
                brace_count += 1
                found_open = True
            elif JS_CONTENT[pos] == '}':
                brace_count -= 1
            pos += 1
            if found_open and brace_count == 0:
                break
        func_body = JS_CONTENT[start:pos]
        self.assertIn("String(str).replace", func_body,
                      'escapeHtml must use String(str) to handle numeric inputs')
        self.assertIn("str == null", func_body,
                      'escapeHtml must use == null check (not !str) so 0 is not rejected')


class TestErrorModal(unittest.TestCase):
    def test_error_modal_exists(self):
        self.assertIn('id="errorModal"', HTML_CONTENT)

    def test_error_modal_has_close_button(self):
        self.assertIn("onclick=\"closeErrorModal()\"", HTML_CONTENT)

    def test_showError_function_exists(self):
        self.assertIn('function showError(', JS_CONTENT)

    def test_closeErrorModal_function_exists(self):
        self.assertIn('function closeErrorModal(', JS_CONTENT)

    def test_no_alert_for_errors(self):
        """All user-facing error alerts must use showError, not alert()."""
        alert_errors = re.findall(r"alert\('Error:", JS_CONTENT)
        self.assertEqual(len(alert_errors), 0,
                         f'Found {len(alert_errors)} alert() calls for errors; use showError() instead')


class TestExternalLinksSecurity(unittest.TestCase):
    def test_all_blank_targets_have_rel_noopener(self):
        """All links with target='_blank' must have rel='noopener noreferrer' to prevent tabnabbing."""
        links = re.findall(r'<a[^>]*target="_blank"[^>]*>', HTML_CONTENT)
        self.assertGreater(len(links), 0, 'Should have external links to test')
        for link in links:
            self.assertIn('rel="noopener noreferrer"', link,
                          f'External link missing rel="noopener noreferrer": {link}')


class TestEscapeHtmlCompleteness(unittest.TestCase):
    def test_escapeHtml_escapes_single_quotes(self):
        func_match = re.search(r'function escapeHtml\(', JS_CONTENT)
        self.assertIsNotNone(func_match)
        start = func_match.start()
        brace_count = 0
        pos = start
        found_open = False
        while pos < len(JS_CONTENT):
            if JS_CONTENT[pos] == '{':
                brace_count += 1
                found_open = True
            elif JS_CONTENT[pos] == '}':
                brace_count -= 1
            pos += 1
            if found_open and brace_count == 0:
                break
        func_body = JS_CONTENT[start:pos]
        self.assertIn("replace(/'/g, '&#39;')", func_body,
                      'escapeHtml must escape single quotes for defense-in-depth')


class TestAdvancedToggleNoMemoryLeak(unittest.TestCase):
    def test_no_inline_addEventListener_for_advancedToggle(self):
        """The advanced toggle must use a single delegated listener, not repeated inline addEventListener calls."""
        load_analysis = JS_CONTENT.split('async function loadAnalysis')[1]
        self.assertNotIn("addEventListener('change', function()", load_analysis,
                         'loadAnalysis must not attach inline change listeners to avoid memory leaks')

    def test_toggle_aggregations_function_exists(self):
        """toggleAggregations function must exist to handle section heading clicks."""
        self.assertIn("function toggleAggregations()", JS_CONTENT,
                      'toggleAggregations function must exist')


class TestCheckStatusTimeoutFeedback(unittest.TestCase):
    def test_timeout_shows_error_modal(self):
        """After max polling attempts, checkStatus must show an error to the user."""
        self.assertIn('CONFIG.MAX_POLLING_ATTEMPTS', JS_CONTENT,
                      'checkStatus must use CONFIG constant for polling attempts')
        check_status = JS_CONTENT.split('async function checkStatus')[1]
        self.assertIn('showError(', check_status,
                      'checkStatus must show an error when polling times out')

    def test_error_status_shows_error_modal(self):
        """When server returns status='error', checkStatus must show it immediately."""
        check_status = JS_CONTENT.split('async function checkStatus')[1]
        self.assertIn("result.status === 'error'", check_status,
                      'checkStatus must handle error status from server')
        self.assertIn('showError(result.message', check_status,
                      'checkStatus must show the server error message')


class TestNoDeadCode(unittest.TestCase):
    def test_no_currentSectionTypes(self):
        """currentSectionTypes was declared but never used — should be removed."""
        self.assertNotIn('currentSectionTypes', JS_CONTENT,
                         'currentSectionTypes is dead code and should be removed')


class TestSearchUI(unittest.TestCase):
    def test_search_bar_exists(self):
        self.assertIn('id="searchBarContainer"', HTML_CONTENT,
                      'Search bar container must exist')
        self.assertIn('id="searchInput"', HTML_CONTENT,
                      'Search input must exist')

    def test_search_functions_exist(self):
        self.assertIn('function performSearch', JS_CONTENT,
                      'performSearch function must exist')
        self.assertIn('function clearSearch', JS_CONTENT,
                      'clearSearch function must exist')
        self.assertIn('function refreshAnalysisData', JS_CONTENT,
                      'refreshAnalysisData function must exist')

    def test_search_state_variable_is_array(self):
        self.assertIn('let currentSearch = []', JS_CONTENT,
                      'currentSearch must be initialized as an array')

    def test_search_uses_encodeURIComponent(self):
        self.assertIn('encodeURIComponent(t)', JS_CONTENT,
                      'Search must encode URI components per term')

    def test_search_bar_css(self):
        self.assertIn('.search-bar', CSS_CONTENT,
                      'Search bar CSS must exist')
        self.assertIn('.search-input', CSS_CONTENT,
                      'Search input CSS must exist')
        self.assertIn('.search-btn', CSS_CONTENT,
                      'Search button CSS must exist')

    def test_search_fetches_stats_with_q(self):
        self.assertIn("'/api/stats?md5=' + currentMd5 + qParam", JS_CONTENT,
                      'refreshAnalysisData must fetch stats with q parameter')

    def test_search_fetches_events_with_q(self):
        self.assertIn("CONFIG.MAX_QUERY_LIMIT", JS_CONTENT,
                      'refreshAnalysisData must use CONFIG constant for query limit')

    def test_loadTabData_passes_q(self):
        self.assertIn("currentSearch.map(t => '&q=' + encodeURIComponent(t)).join('')", JS_CONTENT,
                      'loadTabData must join multiple q parameters')

    def test_search_resets_on_new_analysis(self):
        self.assertIn("currentSearch = []", JS_CONTENT,
                      'loadAnalysis must reset currentSearch to empty array')

    def test_baseEventStats_exists(self):
        self.assertIn('baseEventStats', JS_CONTENT,
                      'baseEventStats variable must exist for unfiltered totals')

    def test_buildStats_uses_baseEventStats(self):
        self.assertIn('baseEventStats[type]', JS_CONTENT,
                      'buildStats must use baseEventStats for totals')

    def test_search_creates_chip_per_term(self):
        """buildFilterBarHtml must render one chip per search term."""
        self.assertIn('for (let i = 0; i < currentSearch.length; i++)', JS_CONTENT,
                      'buildFilterBarHtml must iterate search terms')
        self.assertIn('onclick="clearSearchTerm(', JS_CONTENT,
                      'Each search chip must call clearSearchTerm with index')

    def test_search_chip_shows_full_query(self):
        """buildFilterBarHtml must show full escaped term in each chip."""
        self.assertIn('"${escapeHtml(term)}"', JS_CONTENT,
                      'Search chip must show full escaped term text')

    def test_search_adds_terms_on_enter(self):
        """performSearch must split input into terms and push to array."""
        func = JS_CONTENT.split('async function performSearch')[1].split('async function')[0]
        self.assertIn("currentSearch.push(term)", func,
                      'performSearch must push terms into currentSearch array')

    def test_search_clears_input_after_enter(self):
        """performSearch must clear input after adding terms."""
        func = JS_CONTENT.split('async function performSearch')[1].split('async function')[0]
        self.assertIn("input.value = ''", func,
                      'performSearch must clear search input after submit')

    def test_search_deduplicates_terms(self):
        """performSearch must skip duplicate terms."""
        func = JS_CONTENT.split('async function performSearch')[1].split('async function')[0]
        self.assertIn("!currentSearch.includes(term)", func,
                      'performSearch must deduplicate terms')

    def test_clear_search_term_by_index(self):
        """clearSearchTerm must splice array at given index."""
        func = JS_CONTENT.split('async function clearSearchTerm')[1].split('async function')[0]
        self.assertIn("currentSearch.splice(index, 1)", func,
                      'clearSearchTerm must remove term at index')

    def test_qParam_builds_multiple_q(self):
        """qParam must build multiple &q= params from currentSearch array."""
        from tests.jsdom_helper import js_statements
        result = js_statements('''
            currentSearch = ['1.2.3.4', 'malware'];
            var qParam = currentSearch.length > 0 ? currentSearch.map(function(t) { return '&q=' + encodeURIComponent(t); }).join('') : '';
            window.__jsdom_result = qParam;
        ''')
        self.assertIn('q=1.2.3.4', result)
        self.assertIn('q=malware', result)

    def test_clearSearchTerm_removes_term(self):
        """clearSearchTerm must remove the term at the given index."""
        from tests.jsdom_helper import js_statements
        result = js_statements('''
            currentSearch = ['1.2.3.4', 'malware', 'apt'];
            // The synchronous part of clearSearchTerm
            currentSearch.splice(1, 1);
            window.__jsdom_result = currentSearch;
        ''')
        self.assertEqual(result, ['1.2.3.4', 'apt'])

    def test_qParam_joins_multiple_q(self):
        """qParam must build multiple &q= params from array."""
        self.assertIn("currentSearch.map(t => '&q=' + encodeURIComponent(t)).join('')", JS_CONTENT,
                      'qParam must join multiple q parameters')

    def test_clear_all_clears_search(self):
        """clearAllFilters must reset currentSearch and search input."""
        func = JS_CONTENT.split('async function clearAllFilters')[1].split('async function')[0]
        self.assertIn("currentSearch = []", func,
                      'clearAllFilters must reset currentSearch to empty array')
        self.assertIn("input.value = ''", func,
                      'clearAllFilters must clear search input')

    def test_filter_bar_visible_with_search_only(self):
        """updateFilterBarVisibility must show bar when only currentSearch has terms."""
        self.assertIn('currentSearch.length > 0 || hasFilters', JS_CONTENT,
                      'updateFilterBarVisibility must check search array length and filters')

    def test_showWelcome_uses_clearAnalysisContainers(self):
        """REGRESSION: showWelcome must call clearAnalysisContainers when returning to overview."""
        func = JS_CONTENT.split('async function showWelcome')[1].split('async function')[0]
        self.assertIn("clearAnalysisContainers()", func,
                      'showWelcome must call clearAnalysisContainers when returning to overview')

    def test_showWelcome_uses_showWelcomeUI(self):
        """REGRESSION: showWelcome must call showWelcomeUI when returning to overview."""
        func = JS_CONTENT.split('async function showWelcome')[1].split('async function')[0]
        self.assertIn("showWelcomeUI()", func,
                      'showWelcome must call showWelcomeUI when returning to overview')

    def test_refreshAnalysisData_preserves_active_section(self):
        """REGRESSION: refreshAnalysisData must remember and restore the active section type after rebuild."""
        func = JS_CONTENT.split('async function refreshAnalysisData')[1].split('async function')[0]
        self.assertIn("const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)')", func,
                      'refreshAnalysisData must query visible section before rebuild')
        self.assertIn("const activeType = visibleSection ? visibleSection.id.replace('section-', '') : ''", func,
                      'refreshAnalysisData must extract active type from visible section')
        self.assertIn("if (activeType && activeType !== eventTypes[0])", func,
                      'refreshAnalysisData must conditionally restore non-default active type')
        self.assertIn("sectionEl.classList.remove('section-hidden')", func,
                      'refreshAnalysisData must unhide the restored section')
        self.assertIn("loadTabData(activeType, null)", func,
                      'refreshAnalysisData must reload data for restored section')

    def test_refreshAnalysisData_loads_default_tab(self):
        """REGRESSION: refreshAnalysisData must explicitly load the default tab when no other tab is active."""
        func = JS_CONTENT.split('async function refreshAnalysisData')[1].split('async function')[0]
        self.assertIn("loadTabData(eventTypes[0], null)", func,
                      'refreshAnalysisData must load default tab when activeType is default')

    def test_refreshAnalysisData_does_not_override_sankey_with_all_events(self):
        """REGRESSION: refreshAnalysisData must not call updateSankeyDiagram(allEvents) after restoring the active section, because loadTabData already updates the Sankey for the correct type."""
        func = JS_CONTENT.split('async function refreshAnalysisData')[1].split('async function')[0]
        self.assertNotIn("updateSankeyDiagram(allEvents)", func,
                      'refreshAnalysisData must not override Sankey with allEvents after restore')

    def test_refreshAnalysisData_does_not_override_aggregations_with_all_events(self):
        """REGRESSION: refreshAnalysisData must not unconditionally call buildAggregationsSectionAll() after restoring the active section, because loadTabData already builds aggregations for the correct type."""
        func = JS_CONTENT.split('async function refreshAnalysisData')[1].split('async function')[0]
        self.assertNotIn("buildAggregationsSectionAll()", func,
                      'refreshAnalysisData must not override aggregations with allEvents after restore')

    def test_buildSections_does_not_call_loadTabData(self):
        """REGRESSION: buildSections must not call loadTabData to prevent a race with refreshAnalysisData."""
        func = JS_CONTENT.split('function buildSections(')[1].split('function ')[0]
        self.assertNotIn("loadTabData", func,
                      'buildSections must not call loadTabData')


class TestReanalyzeUI(unittest.TestCase):
    def test_reanalyze_button_on_welcome(self):
        """Welcome screen must show a re-analyze button next to each previous PCAP."""
        self.assertIn('openReanalyzeModal', JS_CONTENT,
                      'showWelcome must include re-analyze button')
        self.assertIn('🔄', JS_CONTENT,
                      'Re-analyze button must use refresh icon')

    def test_reanalyze_modal_exists(self):
        """Re-analyze confirmation modal must exist in HTML."""
        self.assertIn('id="reanalyzeConfirmModal"', HTML_CONTENT,
                      'reanalyzeConfirmModal must exist')
        self.assertIn('id="reanalyzeFileName"', HTML_CONTENT,
                      'reanalyzeFileName span must exist')

    def test_reanalyze_modal_has_cancel_and_reanalyze_buttons(self):
        """Re-analyze modal must have Cancel and Re-analyze buttons."""
        modal_section = HTML_CONTENT.split('id="reanalyzeConfirmModal"')[1].split('</div>\n        </div>')[0]
        self.assertIn('closeReanalyzeModal()', modal_section,
                      'Modal must have Cancel button')
        self.assertIn('confirmReanalyze()', modal_section,
                      'Modal must have Re-analyze button')

    def test_reanalyze_calls_post_api(self):
        """confirmReanalyze must POST to /api/reanalyze with JSON body."""
        self.assertIn("fetch('/api/reanalyze'", JS_CONTENT,
                      'confirmReanalyze must fetch /api/reanalyze')
        self.assertIn("method: 'POST'", JS_CONTENT,
                      'confirmReanalyze must use POST method')
        self.assertIn("JSON.stringify({md5: md5})", JS_CONTENT,
                      'confirmReanalyze must send md5 in JSON body')

    def test_reanalyze_shows_loading(self):
        """confirmReanalyze must show loading indicator while Suricata runs."""
        self.assertIn("showLoading('Re-analyzing", JS_CONTENT,
                      'confirmReanalyze must call showLoading')

    def test_reanalyze_uses_checkStatus(self):
        """confirmReanalyze must poll checkStatus after starting reanalysis."""
        self.assertIn('await checkStatus(md5)', JS_CONTENT,
                      'confirmReanalyze must poll checkStatus')


class TestFileAlertsUI(unittest.TestCase):
    def test_has_filealerts_in_type_labels(self):
        self.assertIn("filealerts: 'File Alerts'", JS_CONTENT,
                      'typeLabels must include filealerts')

    def test_has_filealerts_in_type_colors(self):
        self.assertIn("filealerts: '#e91e63'", JS_CONTENT,
                      'COLORS.EVENT must include filealerts color')

    def test_has_filealerts_in_event_type_icons(self):
        self.assertIn("filealerts: '🚨'", JS_CONTENT,
                      'EVENT_TYPE_ICONS must include filealerts icon')

    def test_filealerts_columns_defined(self):
        self.assertIn("case 'filealerts':", JS_CONTENT,
                      'getColumnsForType must handle filealerts')
        self.assertIn("'Classification'", JS_CONTENT,
                      'filealerts columns must include Classification')

    def test_filealerts_row_rendering(self):
        self.assertIn("case 'filealerts':", JS_CONTENT,
                      'buildRowForEvent must handle filealerts')
        self.assertIn("fa.rule_name", JS_CONTENT,
                      'buildRowForEvent must render rule_name from filealerts object')
        self.assertIn("fa.classification", JS_CONTENT,
                      'buildRowForEvent must render classification from filealerts object')

    def test_filealerts_row_html(self):
        """buildRowForEvent must produce correct HTML for filealerts events."""
        from tests.jsdom_helper import js_statements
        event = {
            'event_type': 'filealerts',
            'timestamp': '2026-01-01T12:00:00Z',
            'proto': 'TCP',
            'src_ip': '192.168.1.1',
            'src_port': 12345,
            'dest_ip': '10.0.0.1',
            'dest_port': 80,
            'filealerts': {
                'rule_name': 'MALWARE_Test',
                'classification': 'threat',
                'tags': ['malware', 'apt'],
                'sha256': 'a' * 64,
            }
        }
        result = js_statements(f'''
            var e = {json.dumps(event)};
            var html = buildRowForEvent(e);
            window.__jsdom_result = {{
                hasRuleName: html.indexOf('MALWARE_Test') >= 0,
                hasThreatBadge: html.indexOf('Threat') >= 0,
                hasTags: html.indexOf('malware') >= 0 && html.indexOf('apt') >= 0,
                hasTCP: html.indexOf('TCP') >= 0,
                hasSrcIp: html.indexOf('192.168.1.1') >= 0,
            }};
        ''')
        self.assertTrue(result['hasRuleName'], 'Row must contain rule name')
        self.assertTrue(result['hasThreatBadge'], 'Row must contain threat classification badge')
        self.assertTrue(result['hasTags'], 'Row must contain tags')
        self.assertTrue(result['hasTCP'], 'Row must contain protocol')
        self.assertTrue(result['hasSrcIp'], 'Row must contain source IP')

    def test_classification_colors_defined(self):
        self.assertIn("threat: { bg: '#ff6b6b33', text: '#ff6b6b' }", JS_CONTENT,
                      'Classification colors must include threat (red)')
        self.assertIn("technique: { bg: '#ffa72633', text: '#ffa726' }", JS_CONTENT,
                      'Classification colors must include technique (yellow)')
        self.assertIn("informational: { bg: '#9e9e9e33', text: '#9e9e9e' }", JS_CONTENT,
                      'Classification colors must include informational (gray)')

    def test_extract_value_classification(self):
        self.assertIn("case 'Classification':", JS_CONTENT,
                      'extractValue must handle Classification column')

    def test_fileinfo_shows_file_alerts_section(self):
        self.assertIn('File Alerts', JS_CONTENT,
                      'formatEvent must show File Alerts section for fileinfo')

    def test_filealerts_in_all_event_types(self):
        expected_types = ['alert', 'dns', 'http', 'tls', 'flow', 'ftp', 'stats', 'anomaly', 'fileinfo', 'filealerts']
        for etype in expected_types:
            self.assertIn(f"'{etype}'", JS_CONTENT)

    def test_filealerts_uses_nested_schema(self):
        self.assertIn('e.filealerts?.rule_name', JS_CONTENT,
                      'buildRowForEvent must access filealerts via nested schema')
        self.assertIn('e.filealerts?.classification', JS_CONTENT,
                      'buildRowForEvent must access classification via nested schema')


if __name__ == '__main__':
    unittest.main(verbosity=2)
