package org.springframework.security.web.util;

import org.springframework.util.Assert;

/**
 * Internal class for building redirect URLs.
 *
 * Could probably make more use of the classes in java.net for this.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class RedirectUrlBuilder {
    private String scheme;
    private String serverName;
    private int port;
    private String contextPath;
    private String servletPath;
    private String pathInfo;
    private String query;

    public void setScheme(String scheme) {
        if(! ("http".equals(scheme) | "https".equals(scheme)) ) {
            throw new IllegalArgumentException("Unsupported scheme '" + scheme + "'");
        }
        this.scheme = scheme;
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setContextPath(String contextPath) {
        this.contextPath = contextPath;
    }

    public void setServletPath(String servletPath) {
        this.servletPath = servletPath;
    }

    public void setPathInfo(String pathInfo) {
        this.pathInfo = pathInfo;
    }

    public void setQuery(String query) {
        this.query = query;
    }

    public String getUrl() {
        StringBuilder sb = new StringBuilder();

        Assert.notNull(scheme);
        Assert.notNull(serverName);

        sb.append(scheme).append("://").append(serverName);

        // Append the port number if it's not standard for the scheme
        if (port != (scheme.equals("http") ? 80 : 443)) {
            sb.append(":").append(Integer.toString(port));
        }

        if (contextPath != null) {
            sb.append(contextPath);
        }

        if (servletPath != null) {
            sb.append(servletPath);
        }

        if (pathInfo != null) {
            sb.append(pathInfo);
        }

        if (query != null) {
            sb.append("?").append(query);
        }
        
        return sb.toString();
    }
}
