package org.springframework.security.util;

/**
 * Utilities for working with Strings and text.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class TextUtils {

    public static String escapeEntities(String s) {
        if (s == null || s.length() == 0) {
            return s;
        }

        StringBuffer sb = new StringBuffer();

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
            } else {
                sb.append(c);
            }
        }

        return sb.toString();
    }

}
