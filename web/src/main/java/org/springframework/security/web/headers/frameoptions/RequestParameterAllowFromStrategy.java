package org.springframework.security.web.headers.frameoptions;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * Base class for AllowFromStrategy implementations which use a request parameter to retrieve the origin. By default
 * the parameter named <code>from</code> is read from the request.
 *
 * @author Marten Deinum
 * @since 3.2
 */
public abstract class RequestParameterAllowFromStrategy implements AllowFromStrategy {


    private static final String DEFAULT_ORIGIN_REQUEST_PARAMETER = "from";

    private String parameter = DEFAULT_ORIGIN_REQUEST_PARAMETER;

    /** Logger for use by subclasses */
    protected final Log log = LogFactory.getLog(getClass());


    @Override
    public String apply(HttpServletRequest request) {
        String from = request.getParameter(parameter);
        if (log.isDebugEnabled()) {
            log.debug("Supplied origin '"+from+"'");
        }
        if (StringUtils.hasText(from) && allowed(from)) {
            return "ALLOW-FROM " + from;
        } else {
            return "DENY";
        }
    }

    public void setParameterName(String parameter) {
        this.parameter=parameter;
    }

    /**
     * Method to be implemented by base classes, used to determine if the supplied origin is allowed.
     *
     * @param from the supplied origin
     * @return <code>true</code> if the supplied origin is allowed.
     */
    protected abstract boolean allowed(String from);
}
