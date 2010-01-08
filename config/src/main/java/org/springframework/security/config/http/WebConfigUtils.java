package org.springframework.security.config.http;

import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;

/**
 * Utility methods used internally by the Spring Security http namespace configuration code.
 *
 * @author Luke Taylor
 * @author Ben Alex
 */
abstract class WebConfigUtils {

    public static int countNonEmpty(String[] objects) {
        int nonNulls = 0;

        for (int i = 0; i < objects.length; i++) {
            if (StringUtils.hasText(objects[i])) {
                nonNulls++;
            }
        }

        return nonNulls;
    }

    /**
     * Checks the value of an XML attribute which represents a redirect URL.
     * If not empty or starting with "$" (potential placeholder), "/" or "http" it will raise an error.
     */
    static void validateHttpRedirect(String url, ParserContext pc, Object source) {
        if (!StringUtils.hasText(url) || UrlUtils.isValidRedirectUrl(url) || url.startsWith("$")) {
            return;
        }
        pc.getReaderContext().warning(url + " is not a valid redirect URL (must start with '/' or http(s))", source);
    }

}
