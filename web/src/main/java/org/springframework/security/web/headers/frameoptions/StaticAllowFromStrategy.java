package org.springframework.security.web.headers.frameoptions;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;

/**
 * Simple implementation of the {@code AllowFromStrategy}
 */
public class StaticAllowFromStrategy implements AllowFromStrategy {

    private final URI uri;

    public StaticAllowFromStrategy(URI uri) {
        this.uri=uri;
    }

    public String getAllowFromValue(HttpServletRequest request) {
        return uri.toString();
    }
}
