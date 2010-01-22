package org.springframework.security.web.util;

/**
 * Internal utility for escaping characters in HTML strings.
 *
 * @author Luke Taylor
 *
 * @see http://www.owasp.org/index.php/How_to_perform_HTML_entity_encoding_in_Java
 */
public abstract class TextEscapeUtils {

    public final static String escapeEntities(String s) {
        if (s == null || s.length() == 0) {
            return s;
        }

        StringBuilder sb = new StringBuilder();

        for (int i=0; i < s.length(); i++) {
            char c = s.charAt(i);

            if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
                sb.append(c);
            } else if(c == '<') {
                sb.append("&lt;");
            } else if (c == '>') {
                sb.append("&gt;");
            } else if (c == '&') {
                sb.append("&amp;");
            } else if (Character.isWhitespace(c)) {
                sb.append("&#").append((int)c).append(";");
            } else if (Character.isISOControl(c)) {
                // ignore control chars
            } else if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length()) {
                    // Unexpected end
                    throw new IllegalArgumentException("Missing low surrogate character at end of string");
                }
                char low = s.charAt(i + 1);

                if (!Character.isLowSurrogate(low)) {
                    throw new IllegalArgumentException("Expected low surrogate character but found value = " + (int)low);
                }

                int codePoint = Character.toCodePoint(c, low);
                if (Character.isDefined(codePoint)) {
                    sb.append("&#").append(codePoint).append(";");
                }
                i++; // skip the next character as we have already dealt with it
            } else if (Character.isLowSurrogate(c)) {
                throw new IllegalArgumentException("Unexpected low surrogate character, value = " + (int)c);
            } else if (Character.isDefined(c)) {
                sb.append("&#").append((int) c).append(";");
            }
            // Ignore anything else
        }

        return sb.toString();
    }
}
