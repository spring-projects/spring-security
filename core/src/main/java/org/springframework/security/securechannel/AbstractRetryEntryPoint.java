package org.springframework.security.securechannel;

import org.springframework.security.util.PortMapper;
import org.springframework.security.util.PortResolver;
import org.springframework.security.util.PortMapperImpl;
import org.springframework.security.util.PortResolverImpl;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractRetryEntryPoint implements ChannelEntryPoint {
    //~ Static fields/initializers =====================================================================================
    private static final Log logger = LogFactory.getLog(RetryWithHttpEntryPoint.class);

    //~ Instance fields ================================================================================================

    private PortMapper portMapper = new PortMapperImpl();
    private PortResolver portResolver = new PortResolverImpl();
    /** The scheme ("http://" or "https://") */
    private String scheme;
    /** The standard port for the scheme (80 for http, 443 for https) */
    private int standardPort;

    //~ Constructors ===================================================================================================

    public AbstractRetryEntryPoint(String scheme, int standardPort) {
        this.scheme = scheme;
        this.standardPort = standardPort;
    }

    //~ Methods ========================================================================================================

    public void commence(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;

        String pathInfo = request.getPathInfo();
        String queryString = request.getQueryString();
        String contextPath = request.getContextPath();
        String destination = request.getServletPath() + ((pathInfo == null) ? "" : pathInfo)
            + ((queryString == null) ? "" : ("?" + queryString));

        String redirectUrl = contextPath;

        Integer currentPort = new Integer(portResolver.getServerPort(request));
        Integer redirectPort = getMappedPort(currentPort);

        if (redirectPort != null) {
            boolean includePort = redirectPort.intValue() != standardPort;

            redirectUrl = scheme + request.getServerName() + ((includePort) ? (":" + redirectPort) : "") + contextPath
                + destination;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Redirecting to: " + redirectUrl);
        }

        ((HttpServletResponse) res).sendRedirect(((HttpServletResponse) res).encodeRedirectURL(redirectUrl));
    }

    protected abstract Integer getMappedPort(Integer mapFromPort);

    protected PortMapper getPortMapper() {
        return portMapper;
    }

    protected PortResolver getPortResolver() {
        return portResolver;
    }

    public void setPortMapper(PortMapper portMapper) {
        Assert.notNull(portMapper, "portMapper cannot be null");
        this.portMapper = portMapper;
    }

    public void setPortResolver(PortResolver portResolver) {
        Assert.notNull(portResolver, "portResolver cannot be null");
        this.portResolver = portResolver;
    }
}
