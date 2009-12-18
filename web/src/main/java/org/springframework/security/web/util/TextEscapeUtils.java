package org.springframework.security.web.util;

/**
 * Utility for escaping characters in HTML strings.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class TextEscapeUtils {

    public final static String escapeEntities(String s) {
        if (s == null || s.length() == 0) {
            return s;
        }

        StringBuilder sb = new StringBuilder();

        for (int i=0; i < s.length(); i++) {
            char c = s.charAt(i);

            if(c == '<') {
                sb.append("&lt;");
            } else if (c == '>') {
                sb.append("&gt;");
            } else if (c == '"') {
                sb.append("&#034;");
            } else if (c == '\'') {
                sb.append("&#039;");
            } else if (c == '&') {
                sb.append("&amp;");
            } else {
                sb.append(c);
            }
        }

        return sb.toString();
    }

}
