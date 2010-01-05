package org.springframework.security.config.authentication;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.List;

import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.memory.UserMap;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * @author Luke Taylor
 * @author Ben Alex
 */
public class UserServiceBeanDefinitionParser extends AbstractUserDetailsServiceBeanDefinitionParser {

    static final String ATT_PASSWORD = "password";
    static final String ATT_NAME = "name";
    static final String ELT_USER = "user";
    static final String ATT_AUTHORITIES = "authorities";
    static final String ATT_PROPERTIES = "properties";
    static final String ATT_DISABLED = "disabled";
    static final String ATT_LOCKED = "locked";

    private SecureRandom random;

    protected String getBeanClassName(Element element) {
        return "org.springframework.security.core.userdetails.memory.InMemoryDaoImpl";
    }

    @SuppressWarnings("unchecked")
    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        String userProperties = element.getAttribute(ATT_PROPERTIES);
        List<Element> userElts = DomUtils.getChildElementsByTagName(element, ELT_USER);

        if (StringUtils.hasText(userProperties)) {

            if(!CollectionUtils.isEmpty(userElts)) {
                throw new BeanDefinitionStoreException("Use of a properties file and user elements are mutually exclusive");
            }

            BeanDefinition bd = new RootBeanDefinition(PropertiesFactoryBean.class);
            bd.getPropertyValues().addPropertyValue("location", userProperties);
            builder.addPropertyValue("userProperties", bd);

            return;
        }

        if(CollectionUtils.isEmpty(userElts)) {
            throw new BeanDefinitionStoreException("You must supply user definitions, either with <" + ELT_USER + "> child elements or a " +
                "properties file (using the '" + ATT_PROPERTIES + "' attribute)" );
        }

        BeanDefinition userMap = new RootBeanDefinition(UserMap.class);
        ManagedMap<String, BeanDefinition> users = new ManagedMap<String, BeanDefinition>();

        for (Iterator i = userElts.iterator(); i.hasNext();) {
            Element userElt = (Element) i.next();
            String userName = userElt.getAttribute(ATT_NAME);
            String password = userElt.getAttribute(ATT_PASSWORD);

            if (!StringUtils.hasLength(password)) {
                password = generateRandomPassword();
            }

            boolean locked = "true".equals(userElt.getAttribute(ATT_LOCKED));
            boolean disabled = "true".equals(userElt.getAttribute(ATT_DISABLED));
            BeanDefinitionBuilder authorities = BeanDefinitionBuilder.rootBeanDefinition(AuthorityUtils.class);
            authorities.addConstructorArgValue(userElt.getAttribute(ATT_AUTHORITIES));
            authorities.setFactoryMethod("commaSeparatedStringToAuthorityList");

            BeanDefinitionBuilder user = BeanDefinitionBuilder.rootBeanDefinition(User.class);
            user.addConstructorArgValue(userName);
            user.addConstructorArgValue(password);
            user.addConstructorArgValue(!disabled);
            user.addConstructorArgValue(true);
            user.addConstructorArgValue(true);
            user.addConstructorArgValue(!locked);
            user.addConstructorArgValue(authorities.getBeanDefinition());

            users.put(userName, user.getBeanDefinition());
        }

        userMap.getPropertyValues().addPropertyValue("users", users);

        builder.addPropertyValue("userMap", userMap);
    }

    private String generateRandomPassword() {
        if (random == null) {
            try {
                random = SecureRandom.getInstance("SHA1PRNG");
            } catch (NoSuchAlgorithmException e) {
                // Shouldn't happen...
                throw new RuntimeException("Failed find SHA1PRNG algorithm!");
            }
        }
        return Long.toString(random.nextLong());
    }
}
