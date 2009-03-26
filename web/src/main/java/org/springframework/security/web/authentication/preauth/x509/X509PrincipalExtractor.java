package org.springframework.security.web.authentication.preauth.x509;

import java.security.cert.X509Certificate;

/**
 * Obtains the principal from an X509Certificate for use within the framework.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public interface X509PrincipalExtractor {

    /**
     * Returns the principal (usually a String) for the given certificate.
     */
    Object extractPrincipal(X509Certificate cert);
}
