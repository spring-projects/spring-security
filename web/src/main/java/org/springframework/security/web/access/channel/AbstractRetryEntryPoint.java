package org.springframework.security.web.access.channel;

import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Luke Taylor
 */
public abstract class AbstractRetryEntryPoint implements ChannelEntryPoint {
    //~ Static fields/initializers =====================================================================================
    protected final Log logger = LogFactory.getLog(getClass());

    //~ Instance fields ================================================================================================

    private PortMapper portMapper = new PortMapperImpl();
    private PortResolver portResolver = new PortResolverImpl();
    /** The scheme ("http://" or "https://") */
    private final String scheme;
    /** The standard port for the scheme (80 for http, 443 for https) */
    private final int standardPort;

    //~ Constructors ===================================================================================================

    public AbstractRetryEntryPoint(String scheme, int standardPort) {
        this.scheme = scheme;
        this.standardPort = standardPort;
    }

    //~ Methods ========================================================================================================

    public void commence(HttpServletRequest request, HttpServletResponse res) throws IOException, ServletException {
        String queryString = request.getQueryString();
        String redirectUrl = request.getRequestURI() + ((queryString == null) ? "" : ("?" + queryString));

        Integer currentPort = new Integer(portResolver.getServerPort(request));
        Integer redirectPort = getMappedPort(currentPort);

        if (redirectPort != null) {
            boolean includePort = redirectPort.intValue() != standardPort;

            redirectUrl = scheme + request.getServerName() + ((includePort) ? (":" + redirectPort) : "") + redirectUrl;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Redirecting to: " + redirectUrl);
        }

        res.sendRedirect(res.encodeRedirectURL(redirectUrl));
    }

    protected abstract Integer getMappedPort(Integer mapFromPort);

    protected final PortMapper getPortMapper() {
        return portMapper;
    }

    protected final PortResolver getPortResolver() {
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
