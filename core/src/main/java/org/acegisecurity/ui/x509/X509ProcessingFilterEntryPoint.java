package net.sf.acegisecurity.ui.x509;

import net.sf.acegisecurity.intercept.web.AuthenticationEntryPoint;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.providers.x509.X509AuthenticationProvider;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.ServletException;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 *
 * @author Luke Taylor
 */
public class X509ProcessingFilterEntryPoint implements AuthenticationEntryPoint {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(X509ProcessingFilterEntryPoint.class);

    public void commence(ServletRequest request, ServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        logger.debug("commence called: request = [" + request +"] exception ["+ authException + "]");
    }
}
