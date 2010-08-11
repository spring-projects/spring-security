package org.springframework.security.config.http;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @author Ben Alex
 */
class RememberMeBeanDefinitionParser implements BeanDefinitionParser {
    static final String ATT_DATA_SOURCE = "data-source-ref";
    static final String ATT_SERVICES_REF = "services-ref";
    static final String ATT_SERVICES_ALIAS = "services-alias";
    static final String ATT_TOKEN_REPOSITORY = "token-repository-ref";
    static final String ATT_USER_SERVICE_REF = "user-service-ref";
    static final String ATT_TOKEN_VALIDITY = "token-validity-seconds";
    static final String ATT_SECURE_COOKIE = "use-secure-cookie";

    protected final Log logger = LogFactory.getLog(getClass());
    private String servicesName;
    private final String key;

    RememberMeBeanDefinitionParser(String key) {
        this.key = key;
    }

    public BeanDefinition parse(Element element, ParserContext pc) {
        CompositeComponentDefinition compositeDef =
            new CompositeComponentDefinition(element.getTagName(), pc.extractSource(element));
        pc.pushContainingComponent(compositeDef);

        String tokenRepository = element.getAttribute(ATT_TOKEN_REPOSITORY);
        String dataSource = element.getAttribute(ATT_DATA_SOURCE);
        String userServiceRef = element.getAttribute(ATT_USER_SERVICE_REF);
        String rememberMeServicesRef = element.getAttribute(ATT_SERVICES_REF);
        String tokenValiditySeconds = element.getAttribute(ATT_TOKEN_VALIDITY);
        Object source = pc.extractSource(element);

        RootBeanDefinition services = null;

        boolean dataSourceSet = StringUtils.hasText(dataSource);
        boolean tokenRepoSet = StringUtils.hasText(tokenRepository);
        boolean servicesRefSet = StringUtils.hasText(rememberMeServicesRef);
        boolean userServiceSet = StringUtils.hasText(userServiceRef);
        boolean tokenValiditySet = StringUtils.hasText(tokenValiditySeconds);

        if (servicesRefSet && (dataSourceSet || tokenRepoSet || userServiceSet || tokenValiditySet)) {
            pc.getReaderContext().error(ATT_SERVICES_REF + " can't be used in combination with attributes "
                    + ATT_TOKEN_REPOSITORY + "," + ATT_DATA_SOURCE + ", " + ATT_USER_SERVICE_REF + " or " + ATT_TOKEN_VALIDITY, source);
        }

        if (dataSourceSet && tokenRepoSet) {
            pc.getReaderContext().error("Specify " + ATT_TOKEN_REPOSITORY + " or " +
                    ATT_DATA_SOURCE +" but not both", source);
        }

        boolean isPersistent = dataSourceSet | tokenRepoSet;

        if (isPersistent) {
            Object tokenRepo;
            services = new RootBeanDefinition(PersistentTokenBasedRememberMeServices.class);

            if (tokenRepoSet) {
                tokenRepo = new RuntimeBeanReference(tokenRepository);
            } else {
                tokenRepo = new RootBeanDefinition(JdbcTokenRepositoryImpl.class);
                ((BeanDefinition)tokenRepo).getPropertyValues().addPropertyValue("dataSource",
                        new RuntimeBeanReference(dataSource));
            }
            services.getPropertyValues().addPropertyValue("tokenRepository", tokenRepo);
        } else if (!servicesRefSet) {
            services = new RootBeanDefinition(TokenBasedRememberMeServices.class);
        }

        if (services != null) {
            RootBeanDefinition uds = new RootBeanDefinition();
            uds.setFactoryBeanName(BeanIds.USER_DETAILS_SERVICE_FACTORY);
            uds.setFactoryMethodName("cachingUserDetailsService");
            uds.getConstructorArgumentValues().addGenericArgumentValue(userServiceRef);

            services.getPropertyValues().addPropertyValue("userDetailsService", uds);

            if ("true".equals(element.getAttribute(ATT_SECURE_COOKIE))) {
                services.getPropertyValues().addPropertyValue("useSecureCookie", true);
            }

            if (tokenValiditySet) {
                Integer tokenValidity = Integer.valueOf(tokenValiditySeconds);
                if (tokenValidity.intValue() < 0 && isPersistent) {
                    pc.getReaderContext().error(ATT_TOKEN_VALIDITY + " cannot be negative if using" +
                            " a persistent remember-me token repository", source);
                }
                services.getPropertyValues().addPropertyValue("tokenValiditySeconds", tokenValidity);
            }
            services.setSource(source);
            services.getPropertyValues().addPropertyValue("key", key);
            servicesName = pc.getReaderContext().generateBeanName(services);
            pc.registerBeanComponent(new BeanComponentDefinition(services, servicesName));
        } else {
            servicesName = rememberMeServicesRef;
        }

        if (StringUtils.hasText(element.getAttribute(ATT_SERVICES_ALIAS))) {
            pc.getRegistry().registerAlias(servicesName, element.getAttribute(ATT_SERVICES_ALIAS));
        }

        BeanDefinition filter = createFilter(pc, source);
        pc.popAndRegisterContainingComponent();

        return filter;
    }

    private BeanDefinition createFilter(ParserContext pc, Object source) {
        BeanDefinitionBuilder filter = BeanDefinitionBuilder.rootBeanDefinition(RememberMeAuthenticationFilter.class);
        filter.getRawBeanDefinition().setSource(source);
        filter.addPropertyReference("rememberMeServices", servicesName);

        return filter.getBeanDefinition();
    }
}
