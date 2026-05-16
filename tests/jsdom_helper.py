#!/usr/bin/env python3
"""Helper for running JavaScript tests in a JSDOM environment.

This module provides a way to execute ohmypcap.js functions in a Node.js/JSDOM
context from Python unit tests, enabling behavioral testing instead of
brittle string-grep tests.
"""

import json
import os
import subprocess
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
HTML_PATH = os.path.join(PROJECT_ROOT, 'ohmypcap.html')
JS_PATH = os.path.join(PROJECT_ROOT, 'static', 'ohmypcap.js')
CSS_PATH = os.path.join(PROJECT_ROOT, 'static', 'ohmypcap.css')
NODE_MODULES = os.path.join(PROJECT_ROOT, 'node_modules')


def load_files():
    """Load HTML, JS, and CSS content."""
    with open(HTML_PATH, 'r') as f:
        html = f.read()
    with open(JS_PATH, 'r') as f:
        js = f.read()
    with open(CSS_PATH, 'r') as f:
        css = f.read()
    return html, js, css


def run_jsdom_test(js_test_code, setup_code=''):
    """Execute JS test code in a JSDOM environment with ohmypcap loaded.

    Args:
        js_test_code: The JS code to evaluate. Must assign its result to window.__jsdom_result.
        setup_code: Optional JS code to run before the test.

    Returns:
        The parsed JSON result from the JS execution.

    Raises:
        RuntimeError: If the JS execution fails or returns invalid JSON.
    """
    html, js, css = load_files()

    # Build the Node.js script
    node_script = f'''
const {{ JSDOM }} = require('jsdom');

const htmlContent = {json.dumps(html)};
const jsContent = {json.dumps(js)};
const cssContent = {json.dumps(css)};

const dom = new JSDOM(htmlContent, {{
    runScripts: 'dangerously',
    url: 'http://localhost:8000',
    pretendToBeVisual: true,
    resources: 'usable'
}});

const window = dom.window;
const document = window.document;

// Mock fetch before loading JS (prevents init() from failing)
window.fetch = function() {{ return Promise.resolve({{ json: () => Promise.resolve([]) }}); }};

// Inject CSS into the DOM
const styleEl = document.createElement('style');
styleEl.textContent = cssContent;
document.head.appendChild(styleEl);

// Make globals available
window.document = document;

// Run the main JS file via window.eval
window.eval(jsContent);

// Run setup code in window context if provided
{setup_code}

// Run the test code in window context and capture result
// The test code must assign its result to window.__jsdom_result
try {{
    window.eval({json.dumps(js_test_code)});
}} catch(e) {{
    window.__jsdom_result = {{__jsdom_error: e.message, __jsdom_stack: e.stack}};
}}
const __jsdom_result = window.__jsdom_result;
delete window.__jsdom_result;

// Handle undefined and other non-JSON values
if (__jsdom_result === undefined) {{
    console.log(JSON.stringify({{__jsdom_undefined: true}}));
}} else {{
    console.log(JSON.stringify(__jsdom_result));
}}
'''

    env = os.environ.copy()
    env['NODE_PATH'] = NODE_MODULES

    # Write script to temp file (avoids "Argument list too long" error)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False, dir=PROJECT_ROOT) as f:
        f.write(node_script)
        script_path = f.name

    try:
        result = subprocess.run(
            ['node', script_path],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            env=env
        )
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass

    if result.returncode != 0:
        raise RuntimeError(f'JSDOM test failed: {result.stderr}')

    output = result.stdout.strip()
    if not output:
        raise RuntimeError('JSDOM test returned empty output')

    try:
        parsed = json.loads(output)
    except json.JSONDecodeError as e:
        raise RuntimeError(f'JSDOM test returned invalid JSON: {output[:200]}... Error: {e}')

    if isinstance(parsed, dict):
        if '__jsdom_error' in parsed:
            raise RuntimeError(f'JSDOM JS error: {parsed["__jsdom_error"]}')
        if '__jsdom_undefined' in parsed:
            return None

    return parsed


def call_js_function(func_name, *args, setup_code=''):
    """Call a named JS function with arguments and return the result.

    Args:
        func_name: The name of the function to call (must be in global scope).
        *args: JSON-serializable arguments to pass to the function.
        setup_code: Optional setup JS code.

    Returns:
        The parsed JSON result.
    """
    args_json = json.dumps(args)
    js_code = f'window.__jsdom_result = {func_name}.apply(null, {args_json});'
    return run_jsdom_test(js_code, setup_code)


def js_expression(expr, setup_code=''):
    """Evaluate a JS expression and return the result.

    Args:
        expr: A single JS expression (no statements) that evaluates to a JSON-serializable value.
        setup_code: Optional setup JS code.

    Returns:
        The parsed JSON result.
    """
    js_code = f'window.__jsdom_result = {expr};'
    return run_jsdom_test(js_code, setup_code)


def js_statements(code, setup_code=''):
    """Execute JS statements and return the value assigned to window.__jsdom_result.

    Args:
        code: JS statements. Must assign the result to window.__jsdom_result.
        setup_code: Optional setup JS code.

    Returns:
        The parsed JSON result.
    """
    return run_jsdom_test(code, setup_code)
