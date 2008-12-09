package org.springframework.security.config;

import org.springframework.security.ui.preauth.PreAuthenticatedProcessingFilterEntryPoint;
import org.springframework.security.ui.preauth.x509.X509PreAuthenticatedProcessingFilter;
import org.springframework.security.ui.preauth.x509.SubjectDnX509PrincipalExtractor;
import org.springframework.security.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.providers.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.util.StringUtils;

import org.w3c.dom.Element;

/**
 * Parses x509 element in namespace, registering an {@link X509PreAuthenticatedProcessingFilter} instance and a
 * {@link PreAuthenticatedProcessingFilterEntryPoint}.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class X509BeanDefinitionParser implements BeanDefinitionParser {
    public static final String ATT_REGEX = "subject-principal-regex";
    public static final String ATT_USER_SERVICE_REF = "user-service-ref";

    public BeanDefinition parse(Element element, ParserContext parserContext) {
        BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(X509PreAuthenticatedProcessingFilter.class);
        RootBeanDefinition entryPoint = new RootBeanDefinition(PreAuthenticatedProcessingFilterEntryPoint.class);

        Object source = parserContext.extractSource(element);
        filterBuilder.getRawBeanDefinition().setSource(source);
        entryPoint.setSource(source);

        String regex = element.getAttribute(ATT_REGEX);

        if (StringUtils.hasText(regex)) {
            SubjectDnX509PrincipalExtractor extractor = new SubjectDnX509PrincipalExtractor();
            extractor.setSubjectDnRegex(regex);

            filterBuilder.addPropertyValue("principalExtractor", extractor);
        }

        BeanDefinition provider = new RootBeanDefinition(PreAuthenticatedAuthenticationProvider.class);
        parserContext.getRegistry().registerBeanDefinition(BeanIds.X509_AUTH_PROVIDER, provider);
        ConfigUtils.addAuthenticationProvider(parserContext, BeanIds.X509_AUTH_PROVIDER);

        String userServiceRef = element.getAttribute(ATT_USER_SERVICE_REF);

        if (StringUtils.hasText(userServiceRef)) {
            RootBeanDefinition preAuthUserService = new RootBeanDefinition(UserDetailsByNameServiceWrapper.class);
            preAuthUserService.setSource(source);
            preAuthUserService.getPropertyValues().addPropertyValue("userDetailsService", new RuntimeBeanReference(userServiceRef));
            provider.getPropertyValues().addPropertyValue("preAuthenticatedUserDetailsService", preAuthUserService);
        }

        parserContext.getRegistry().registerBeanDefinition(BeanIds.PRE_AUTH_ENTRY_POINT, entryPoint);

        filterBuilder.addPropertyValue("authenticationManager", new RuntimeBeanReference(BeanIds.AUTHENTICATION_MANAGER));

        parserContext.getRegistry().registerBeanDefinition(BeanIds.X509_FILTER, filterBuilder.getBeanDefinition());
        ConfigUtils.addHttpFilter(parserContext, new RuntimeBeanReference(BeanIds.X509_FILTER));

        return null;
    }
}
