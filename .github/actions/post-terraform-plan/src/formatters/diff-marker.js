/**
 * Diff Marker Module
 *
 * Determines the appropriate marker for diff display based on action type and context.
 */

/**
 * Determine the appropriate marker for a change line
 * @param {boolean} beforeExists - Whether the attribute exists in before state
 * @param {boolean} afterExists - Whether the attribute exists in after state
 * @param {string|null} forceMarker - Forced marker if specified
 * @param {boolean} isReplace - Whether this is a replace action
 * @returns {string} The marker to use ('+', '-', '!', '!!', '  ')
 */
function determineMarker(beforeExists, afterExists, forceMarker, isReplace) {
  // For create/destroy: use no markers
  if (forceMarker === '  ' || forceMarker === '') {
    return '  ';
  }

  // Explicit forced marker
  if (forceMarker === '+' || forceMarker === '-') {
    return forceMarker;
  }

  // Update/replace mode - compute markers dynamically
  if (isReplace) {
    return '!!';
  }
  if (!beforeExists && afterExists) {
    return '+';
  }
  if (beforeExists && !afterExists) {
    return '-';
  }
  return '!';
}

/**
 * Get the resource header marker based on action type
 * @param {string} action - Action type (create, update, destroy, replace)
 * @returns {string} The resource header marker
 */
function getResourceHeaderMarker(action) {
  const markers = {
    'create': '+',
    'destroy': '-',
    'replace': '-/+',
    'update': '~'
  };
  return markers[action] || '~';
}

/**
 * Check if markers should be used for nested blocks
 * @param {string|null} forceMarker - Forced marker if specified
 * @returns {boolean} True if markers should be used
 */
function shouldUseMarkersForBlocks(forceMarker) {
  // Original logic: !forceMarker || (forceMarker !== '  ' && forceMarker !== '')
  // This means: use markers if forceMarker is falsy (null, undefined, '') OR if it's not '  ' or ''
  if (!forceMarker) {
    return true; // null, undefined, '' means use markers
  }
  return forceMarker !== '  ' && forceMarker !== '';
}

module.exports = {
  determineMarker,
  getResourceHeaderMarker,
  shouldUseMarkersForBlocks
};
