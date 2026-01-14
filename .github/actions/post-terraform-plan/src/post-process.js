/**
 * Post-Processing Module for Consistent Indentation
 *
 * Takes raw output lines and applies consistent 4-space indentation
 * based on resource/block structure using a clean state-machine approach.
 */

/**
 * Apply consistent 4-space indentation to Terraform plan output.
 *
 * The algorithm:
 * 1. Track nesting level based on opening/closing braces
 * 2. Resource headers are at column 0 (no indent)
 * 3. First level inside resource gets 4 spaces
 * 4. Each nested level adds 4 more spaces
 * 5. Closing braces match their opening level
 *
 * @param {string[]} lines - Raw lines with markers (+, -, !, !!, etc.)
 * @returns {string[]} Lines with consistent 4-space indentation
 */
function applyIndentation(lines) {
  const result = [];
  let depth = 0;           // Current nesting depth (0 = outside resource, 1 = first level, etc.)
  let resourceMarker = '  '; // Marker for current resource ('+' for create, '-' for destroy, etc.)
  let inResourceBlock = false;

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];

    // Remove any existing indentation (we'll rebuild it cleanly)
    const dedented = line.replace(/^[\t ]*/, '');
    const trimmed = dedented.trimEnd();

    // Skip empty lines
    if (trimmed === '') {
      result.push('');
      continue;
    }

    // Match comments - preserve with indentation but no marker
    const commentMatch = trimmed.match(/^(!!|[!+\-])?\s*(#.*)$/);
    if (commentMatch) {
      const comment = commentMatch[2];
      // depth=1 -> 4 spaces, depth=2 -> 8 spaces
      const indent = '    '.repeat(Math.max(0, depth));
      result.push(`${indent}${comment}`);
      continue;
    }

    // Detect resource block header: "resource "type" "name" {"
    // Match '!!' before regular markers
    const resourceMatch = trimmed.match(/^(!!|[!+\-])?\s*(resource\s+"[^"]+"\s+"[^"]+"\s*\{)/);
    if (resourceMatch) {
      resourceMarker = resourceMatch[1] || '  ';
      inResourceBlock = true;
      depth = 1;  // After opening {, we're at depth 1

      // Resource headers have no indentation
      result.push(trimmed);
      continue;
    }

    // Detect closing resource brace (outermost "}") - check content without marker
    const markerCheck = trimmed.match(/^(!!|[!+\-])?\s*/);
    const bareContent = trimmed.replace(/^(!!|[!+\-])?\s*/, '');
    if (bareContent === '}' && inResourceBlock && depth === 1) {
      inResourceBlock = false;
      depth = 0;
      // Preserve marker from input if present, otherwise use spaces
      if (markerCheck[1] && (markerCheck[1] === '+' || markerCheck[1] === '-' || markerCheck[1] === '!' || markerCheck[1] === '!!')) {
        result.push(`${markerCheck[1]} }`);
      } else {
        result.push('  }');
      }
      continue;
    }

    // Extract marker first - match '!!' before single markers
    const markerMatch = trimmed.match(/^(!!|[!+\-])/);
    let marker = markerMatch ? markerMatch[1] : '  ';

    // Extract content WITHOUT marker and any following whitespace
    // This: '!! display_name = "value"' -> 'display_name = "value"'
    const contentMatch = trimmed.match(/^(!!|[!+\-])?\s*(.*)$/s);
    const content = contentMatch ? contentMatch[2] : '';

    // Count braces and brackets in content
    const openBraces = (content.match(/\{/g) || []).length;
    const closeBraces = (content.match(/\}/g) || []).length;
    const openBrackets = (content.match(/\[/g) || []).length;
    const closeBrackets = (content.match(/\]/g) || []).length;

    // Determine if this line closes a structure (nested block or array)
    // Closing structures should be indented at the outer level
    let indentDepth = depth;
    const closesBlock = content === '}' && depth > 1;

    // Check for closing brace (nested block)
    if (closesBlock) {
      indentDepth = depth - 1;
    }
    // Check for closing bracket (array)
    // If closing bracket exists and no opening bracket, it's closing the array
    else if (closeBrackets > openBrackets && openBraces === 0) {
      indentDepth = depth - 1;
    }

    // Calculate indentation
    // depth = 1 means first level inside resource -> 5 spaces (marker + 5 content)
    // depth = 2 means second level -> 9 spaces (add 4 per level)
    // Formula: 1 base space + 4 spaces per depth level
    const indent = '    '.repeat(indentDepth) + ' ';

    // For create/destroy (marker is + or -), use resource-level marker for unmarked lines
    // For update/replace (marker is ! or !!), preserve unmarked lines as-is
    if (marker === '  ' && inResourceBlock && (resourceMarker === '+' || resourceMarker === '-')) {
      marker = resourceMarker;
    }

    // Build output - marker followed directly by indent (no extra space)
    if (marker && marker !== '  ') {
      result.push(`${marker}${indent}${content}`);
    } else {
      result.push(`${indent}${content}`);
    }

    // Update depth for next line
    // Opening braces/brackets increase future depth
    if (openBraces > 0 && openBraces > closeBraces) {
      depth += openBraces - closeBraces;
    } else if (openBrackets > 0 && openBrackets > closeBrackets) {
      depth++;
    }

    // Closing braces decrease depth
    if (closesBlock) {
      depth--;
    } else if (depth > 1 && closeBrackets > openBrackets && openBraces === 0) {
      // Array closing
      depth--;
    }
  }

  return result;
}

module.exports = {
  applyIndentation
};
