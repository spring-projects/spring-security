package org.springframework.security.web.authentication.preauth.x509;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor;

import org.junit.Test;
import org.junit.Before;

import static junit.framework.Assert.*;

/**
 * @author Luke Taylor
 */
public class SubjectDnX509PrincipalExtractorTests {
    SubjectDnX509PrincipalExtractor extractor;

    @Before
    public void setUp() {
        extractor = new SubjectDnX509PrincipalExtractor();
        extractor.setMessageSource(new SpringSecurityMessageSource());
    }

    @Test(expected = IllegalArgumentException.class)
    public void invalidRegexFails() throws Exception {
        extractor.setSubjectDnRegex("CN=(.*?,"); // missing closing bracket on group
    }

    @Test
    public void defaultCNPatternReturnsExcpectedPrincipal() throws Exception {
        Object principal = extractor.extractPrincipal(X509TestUtils.buildTestCertificate());
        assertEquals("Luke Taylor", principal);
    }

    @Test
    public void matchOnEmailReturnsExpectedPrincipal() throws Exception {
        extractor.setSubjectDnRegex("emailAddress=(.*?),");
        Object principal = extractor.extractPrincipal(X509TestUtils.buildTestCertificate());
        assertEquals("luke@monkeymachine", principal);
    }

    @Test(expected = BadCredentialsException.class)
    public void matchOnShoeSizeThrowsBadCredentials() throws Exception {
        extractor.setSubjectDnRegex("shoeSize=(.*?),");
        extractor.extractPrincipal(X509TestUtils.buildTestCertificate());
    }
}
