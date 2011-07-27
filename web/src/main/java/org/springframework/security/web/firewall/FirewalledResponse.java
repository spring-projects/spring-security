package org.springframework.security.web.firewall;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.util.regex.Pattern;

/**
 * @author Luke Taylor
 */
class FirewalledResponse extends HttpServletResponseWrapper {
    Pattern CR_OR_LF = Pattern.compile("\\r|\\n");

    public FirewalledResponse(HttpServletResponse response) {
        super(response);
    }

    @Override
    public void sendRedirect(String location) throws IOException {
        // TODO: implement pluggable validation, instead of simple blacklisting.
        // SEC-1790. Prevent redirects containing CRLF
        if (CR_OR_LF.matcher(location).find()) {
            throw new IllegalArgumentException("Invalid characters (CR/LF) in redirect location");
        }
        super.sendRedirect(location);
    }
}
