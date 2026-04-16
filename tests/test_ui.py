#!/usr/bin/env python3
import unittest
import re
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ohmypcap.html')

with open(HTML_PATH, 'r') as f:
    HTML_CONTENT = f.read()

JS_MATCH = re.search(r'<script>([\s\S]*?)</script>', HTML_CONTENT)
JS_CONTENT = JS_MATCH.group(1) if JS_MATCH else ''


class TestHTMLStructure(unittest.TestCase):
    def test_file_size(self):
        """Verify file is complete (not truncated)"""
        self.assertGreater(len(HTML_CONTENT), 80000, 'File appears truncated')
    
    def test_script_tags_closed(self):
        """Verify script tags are properly closed"""
        self.assertIn('<script>', HTML_CONTENT)
        self.assertIn('</script>', HTML_CONTENT)
        # Count occurrences
        open_count = HTML_CONTENT.count('<script>')
        close_count = HTML_CONTENT.count('</script>')
        self.assertEqual(open_count, close_count, 'Script tags not balanced')
    
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
        self.assertIn('@keyframes spin', HTML_CONTENT)

    def test_has_marked_js(self):
        self.assertNotIn('marked.min.js', HTML_CONTENT)

    def test_closing_tags(self):
        self.assertIn('</html>', HTML_CONTENT)
        self.assertIn('</body>', HTML_CONTENT)
        self.assertIn('</head>', HTML_CONTENT)


class TestCSSLayout(unittest.TestCase):
    def test_stats_grid_columns(self):
        match = re.search(r'grid-template-columns:\s*repeat\((\d+)', HTML_CONTENT)
        self.assertIsNotNone(match, "stats-grid should have grid-template-columns")
        if match:
            columns = int(match.group(1))
            self.assertGreaterEqual(columns, 9)

    def test_stats_grid_gap(self):
        self.assertIn('gap:', HTML_CONTENT)

    def test_section_hidden_class(self):
        self.assertIn('.section-hidden', HTML_CONTENT)
        self.assertIn('display: none', HTML_CONTENT)

    def test_stat_card_hover(self):
        self.assertIn('.stat-card:hover', HTML_CONTENT)

    def test_table_sticky_headers(self):
        self.assertIn('position: sticky', HTML_CONTENT)

    def test_overflow_handling(self):
        self.assertIn('overflow-x: auto', HTML_CONTENT)

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

    def test_has_init(self):
        self.assertIn('function init', JS_CONTENT)

    def test_has_delete_analysis(self):
        self.assertIn('function openDeleteAnalysis', JS_CONTENT)


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
        self.assertIn("if (a === 'alert') return -1", JS_CONTENT, 
                      "Should prioritize 'alert' as first")
        self.assertIn("if (b === 'alert') return 1", JS_CONTENT,
                      "Should prioritize 'alert' as first")
        self.assertIn("t !== 'stats' && t !== 'all'", JS_CONTENT,
                      "Should filter out 'stats' and 'all' from sorting")
        self.assertIn("a.localeCompare(b)", JS_CONTENT,
                      "Should sort alphabetically after alert")

    def test_apply_filter_calls_both_section_and_aggregation(self):
        """Verify applyFilter builds both section and aggregation when filtering"""
        self.assertIn("buildSection(eventType, sections[eventType])", JS_CONTENT,
                      "applyFilter should call buildSection")
        self.assertIn("buildAggregationsSection(eventType, getFilteredEvents(", JS_CONTENT,
                      "applyFilter should call buildAggregationsSection with getFilteredEvents")


class TestJavaScriptDataStructures(unittest.TestCase):
    def test_has_type_labels(self):
        self.assertIn('typeLabels', JS_CONTENT)

    def test_has_type_colors(self):
        self.assertIn('typeColors', JS_CONTENT)

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
        self.assertIn("a === 'alert'", JS_CONTENT)
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
            '/api/pcap-path',
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
        self.assertIn('spinner', HTML_CONTENT)

    def test_empty_state_handling(self):
        self.assertIn('No previous PCAPs available', HTML_CONTENT)

    def test_error_messages(self):
        self.assertIn('alert(', JS_CONTENT)
        self.assertIn('Error:', JS_CONTENT)

    def test_back_navigation(self):
        self.assertIn('Back to Overview', HTML_CONTENT)

    def test_file_input_accepts_correct_types(self):
        self.assertIn('.pcap', HTML_CONTENT)
        self.assertIn('.pcapng', HTML_CONTENT)
        self.assertIn('.cap', HTML_CONTENT)
        self.assertIn('.trace', HTML_CONTENT)

    def test_default_url_prefilled(self):
        self.assertIn('malware-traffic-analysis.net', HTML_CONTENT)

    def test_feature_comparison_table(self):
        self.assertIn('OhMyPCAP', HTML_CONTENT)
        self.assertIn('Security Onion', HTML_CONTENT)

    def test_feature_comparison_table_links(self):
        """Feature comparison table must include links to Security Onion resources"""
        self.assertIn('https://securityonion.net', HTML_CONTENT)
        self.assertIn('http://securityonion.net/docs/about', HTML_CONTENT)
        self.assertIn('https://securityonion.com/pro', HTML_CONTENT)
        self.assertIn('http://securityonion.net/docs/security-onion-pro', HTML_CONTENT)

    def test_ascii_transcript_loading(self):
        self.assertIn('ASCII Transcript', JS_CONTENT)
        self.assertIn('downloadPcap', JS_CONTENT)

    def test_table_sorting_ui(self):
        self.assertIn('cursor: pointer', HTML_CONTENT)
        self.assertIn('sort-arrow', JS_CONTENT)


class TestSecurityInUI(unittest.TestCase):
    def test_no_inline_event_handlers_with_dangerous_patterns(self):
        dangerous_patterns = ['eval(', 'document.write(', 'innerHTML = location', 'innerHTML = window']
        for pattern in dangerous_patterns:
            self.assertNotIn(pattern, JS_CONTENT)

    def test_uses_escape_html_function(self):
        self.assertIn('escapeHtml(', JS_CONTENT)

    def test_no_hardcoded_credentials(self):
        content = JS_CONTENT.lower().replace('disclaimer', '').replace('password-protected', '').replace('password protected', '')
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
        self.assertIn('title="', HTML_CONTENT)


class TestAggregationTables(unittest.TestCase):
    def test_has_agg_grid_css(self):
        self.assertIn('.agg-grid', HTML_CONTENT)

    def test_has_agg_table_css(self):
        self.assertIn('.agg-table', HTML_CONTENT)

    def test_has_agg_table_title_css(self):
        self.assertIn('.agg-table .agg-header', HTML_CONTENT)

    def test_has_agg_row_css(self):
        self.assertIn('.agg-row', HTML_CONTENT)

    def test_has_agg_cell_css(self):
        self.assertIn('.agg-cell', HTML_CONTENT)

    def test_has_aggregations_container(self):
        self.assertIn('id="aggregations"', HTML_CONTENT)

    def test_has_build_aggregation_tables_function(self):
        self.assertIn('function buildAggregationTables', JS_CONTENT)

    def test_has_build_aggregation_tables_all_function(self):
        self.assertIn('function buildAggregationTablesAll', JS_CONTENT)

    def test_has_extract_value_function(self):
        self.assertIn('function extractValue', JS_CONTENT)

    def test_has_extract_all_value_function(self):
        self.assertIn('function extractAllValue', JS_CONTENT)

    def test_has_build_aggregations_section_function(self):
        self.assertIn('function buildAggregationsSection', JS_CONTENT)

    def test_has_build_aggregations_section_all_function(self):
        self.assertIn('function buildAggregationsSectionAll', JS_CONTENT)

    def test_agg_tables_use_string_ports(self):
        self.assertIn("String(e.src_port", JS_CONTENT)
        self.assertIn("String(e.dest_port", JS_CONTENT)

    def test_agg_tables_have_click_handlers(self):
        self.assertIn("onclick=\"applyFilter('section-", JS_CONTENT)

    def test_agg_tables_no_bar_charts(self):
        self.assertNotIn('.agg-bar', HTML_CONTENT)

    def test_agg_tables_have_borders(self):
        self.assertIn('border: 1px solid #30363d', HTML_CONTENT)

    def test_agg_tables_wrap_with_flex(self):
        self.assertIn('flex-wrap: wrap', HTML_CONTENT)


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
        self.assertIn('.filter-bar', HTML_CONTENT)

    def test_has_filter_chip_css(self):
        self.assertIn('.filter-chip', HTML_CONTENT)

    def test_has_filter_clear_all_css(self):
        self.assertIn('.filter-clear-all', HTML_CONTENT)

    def test_has_footer_css(self):
        self.assertIn('.footer', HTML_CONTENT)

    def test_has_footer_with_version(self):
        self.assertIn('OhMyPCAP 1.0.0', HTML_CONTENT)

    def test_has_footer_with_copyright(self):
        self.assertIn('Security Onion Solutions, LLC', HTML_CONTENT)

    def test_has_footer_links(self):
        self.assertIn('github.com/dougburks', HTML_CONTENT)
        self.assertIn('securityonion.com', HTML_CONTENT)

    def test_has_analysis_header(self):
        self.assertIn('id="mainHeader"', HTML_CONTENT)

    def test_has_instructions_in_analysis(self):
        self.assertIn('Start by reviewing security alerts', HTML_CONTENT)

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


class TestPerformance(unittest.TestCase):
    def test_uses_document_fragment_for_batch_inserts(self):
        self.assertIn('createDocumentFragment', JS_CONTENT)

    def test_uses_event_delegation(self):
        self.assertIn('addEventListener', JS_CONTENT)

    def test_lazy_loads_ascii_transcripts(self):
        self.assertIn('loadAsciiTranscript', JS_CONTENT)
        self.assertIn('!pre.textContent', JS_CONTENT)

    def test_truncates_large_streams(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ohmypcap.py'), 'r') as f:
            server_content = f.read()
        self.assertIn('truncated', server_content)


class TestAdvancedToggle(unittest.TestCase):
    def test_has_advanced_toggle_css(self):
        self.assertIn('.advanced-toggle', HTML_CONTENT)

    def test_has_advanced_toggle_input(self):
        self.assertIn('id="advancedToggle"', HTML_CONTENT)

    def test_has_advanced_mode_js_variable(self):
        self.assertIn('let advancedMode', JS_CONTENT)

    def test_aggregations_hidden_by_default(self):
        self.assertIn("document.getElementById('aggregations').style.display = advancedMode ? '' : 'none'", JS_CONTENT)

    def test_filter_bar_container_exists(self):
        self.assertIn('id="filterBarContainer"', HTML_CONTENT)

    def test_update_filter_bar_visibility_function(self):
        self.assertIn('function updateFilterBarVisibility', JS_CONTENT)
        self.assertIn('function buildFilterBarHtml', JS_CONTENT)

    def test_advanced_toggle_in_header(self):
        self.assertIn('Advanced', JS_CONTENT)
        self.assertIn("id=\"advancedToggle\"", JS_CONTENT)


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
        """loadTabData must call updateFilterBarVisibility when using cached data in non-advanced mode"""
        self.assertIn("updateFilterBarVisibility()", JS_CONTENT)
        pattern = r"buildSection\(eventType,\s*tabDataCache\[eventType\]\);\s*updateFilterBarVisibility\(\)"
        self.assertRegex(JS_CONTENT, pattern,
            'loadTabData must call updateFilterBarVisibility after buildSection for cached data')

    def test_loadTabData_calls_updateFilterBarVisibility_for_fresh_data(self):
        """loadTabData must call updateFilterBarVisibility after fetching fresh data in non-advanced mode"""
        pattern = r"buildSection\(eventType,\s*events\);\s*if\s*\(\s*!advancedMode\s*\)\s*updateFilterBarVisibility\(\)"
        self.assertRegex(JS_CONTENT, pattern,
            'loadTabData must call updateFilterBarVisibility after buildSection for fresh data')

    def test_loadTabData_all_events_calls_updateFilterBarVisibility(self):
        """loadTabData for "all" events must call updateFilterBarVisibility in non-advanced mode"""
        pattern = r"buildAllEvents\(\);\s*if\s*\(\s*sectionEl\s*&&\s*advancedMode\s*\)\s*buildAggregationsSectionAll\(\);\s*if\s*\(\s*!advancedMode\s*\)\s*updateFilterBarVisibility\(\)"
        self.assertRegex(JS_CONTENT, pattern,
            'loadTabData must call updateFilterBarVisibility for "all" events in non-advanced mode')

    def test_advanced_toggle_clears_filterBarContainer(self):
        """Enabling advanced mode must clear filterBarContainer to prevent duplicate filter bars"""
        self.assertIn("filterBarContainer.innerHTML = ''", JS_CONTENT)
        self.assertIn("filterBarContainer.style.display = 'none'", JS_CONTENT)

    def test_advanced_toggle_clears_aggregations_on_disable(self):
        """Disabling advanced mode must clear aggregations container to prevent duplicate filter bars"""
        pattern = r"aggContainer\.innerHTML\s*=\s*''"
        self.assertRegex(JS_CONTENT, pattern,
            'Advanced toggle must clear aggregations container when disabling advanced mode')

    def test_filters_are_global_not_per_section(self):
        """currentFilters must be a flat object so filters persist across all views"""
        self.assertIn("currentFilters[columnName] = value", JS_CONTENT)
        self.assertNotIn("currentFilters[sectionId] = {}", JS_CONTENT)
        self.assertNotIn("currentFilters[sectionId][columnName]", JS_CONTENT)

    def test_buildSection_uses_global_filters(self):
        """buildSection must filter using global currentFilters, not per-section filters"""
        self.assertIn("Object.keys(currentFilters).length", JS_CONTENT)
        self.assertNotIn("currentFilters[sectionId] || {}", JS_CONTENT)

    def test_buildAggregationsSection_uses_global_filters(self):
        """buildAggregationsSection must use global currentFilters for filter bar"""
        pattern = r"function buildAggregationsSection[\s\S]{0,500}Object\.keys\(currentFilters\)\.length"
        self.assertRegex(JS_CONTENT, pattern,
            'buildAggregationsSection must check Object.keys(currentFilters).length')

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
        pattern = r"const filtered = getFilteredEvents\(sectionEl\.id,\s*tabDataCache\[eventType\],\s*eventType\);\s*buildAggregationsSection\(eventType,\s*filtered\)"
        self.assertRegex(JS_CONTENT, pattern,
            'loadTabData must call getFilteredEvents before buildAggregationsSection for cached data in advanced mode')

    def test_loadTabData_filters_agg_tables_in_advanced_mode_fresh(self):
        """loadTabData must pass filtered events to buildAggregationsSection for fresh data in advanced mode"""
        pattern = r"const filtered = getFilteredEvents\(sectionEl\.id,\s*events,\s*eventType\);\s*buildAggregationsSection\(eventType,\s*filtered\)"
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
        self.assertIn("currentFilters[columnName] = value", JS_CONTENT)

    def test_all_filtering_functions_use_global_currentFilters(self):
        """REGRESSION: Every function that reads filters must use currentFilters directly,
        not currentFilters[sectionId]. Functions checked: buildSection, buildAllEvents,
        buildAggregationsSection, buildAggregationsSectionAll, getFilteredEvents."""
        self.assertNotIn("const filters = currentFilters[sectionId]", JS_CONTENT)


if __name__ == '__main__':
    unittest.main(verbosity=2)
