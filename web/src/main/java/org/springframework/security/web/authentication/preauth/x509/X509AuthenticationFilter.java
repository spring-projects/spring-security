package org.springframework.security.web.authentication.preauth.x509;

import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class X509AuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {
    private X509PrincipalExtractor principalExtractor = new SubjectDnX509PrincipalExtractor();

    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        X509Certificate cert = extractClientCertificate(request);

        if (cert == null) {
            return null;
        }

        return principalExtractor.extractPrincipal(cert);
    }

    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return extractClientCertificate(request);
    }

    private X509Certificate extractClientCertificate(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

        if (certs != null && certs.length > 0) {
            if (logger.isDebugEnabled()) {
                logger.debug("X.509 client authentication certificate:" + certs[0]);
            }

            return certs[0];
        }

        if (logger.isDebugEnabled()) {
            logger.debug("No client certificate found in request.");
        }

        return null;
    }

    public void setPrincipalExtractor(X509PrincipalExtractor principalExtractor) {
        this.principalExtractor = principalExtractor;
    }
}
