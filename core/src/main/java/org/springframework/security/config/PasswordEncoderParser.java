package org.springframework.security.config;

import org.springframework.security.providers.encoding.Md4PasswordEncoder;
import org.springframework.security.providers.encoding.Md5PasswordEncoder;
import org.springframework.security.providers.encoding.ShaPasswordEncoder;
import org.springframework.security.providers.encoding.BaseDigestPasswordEncoder;
import org.springframework.security.providers.ldap.authenticator.LdapShaPasswordEncoder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

import org.w3c.dom.Element;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Map;
import java.util.HashMap;

/**
 * Stateful parser for the <password-encoder> element.
 *
 * Will produce a PasswordEncoder and (optionally) a SaltSource.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class PasswordEncoderParser {
    static final String ATT_REF = "ref";
    static final String ATT_HASH = "hash";
    static final String ATT_BASE_64 = "base64";
    static final String OPT_HASH_SHA = "sha";
    static final String OPT_HASH_MD4 = "md4";
    static final String OPT_HASH_MD5 = "md5";
    static final String OPT_HASH_LDAP_SHA = "{sha}";

    static final Map ENCODER_CLASSES;

    static {
        ENCODER_CLASSES = new HashMap();
        ENCODER_CLASSES.put(OPT_HASH_SHA, ShaPasswordEncoder.class);
        ENCODER_CLASSES.put(OPT_HASH_MD4, Md4PasswordEncoder.class);
        ENCODER_CLASSES.put(OPT_HASH_MD5, Md5PasswordEncoder.class);
        ENCODER_CLASSES.put(OPT_HASH_LDAP_SHA, LdapShaPasswordEncoder.class);
    }

    private Log logger = LogFactory.getLog(getClass());

    private BeanMetadataElement passwordEncoder;
    private BeanDefinition saltSource;


    public PasswordEncoderParser(Element element, ParserContext parserContext) {
        parse(element, parserContext);
    }

    private void parse(Element element, ParserContext parserContext) {
        String hash = element.getAttribute(ATT_HASH);
        boolean useBase64 = StringUtils.hasText(element.getAttribute(ATT_BASE_64));

        String ref = element.getAttribute(ATT_REF);

        if (StringUtils.hasText(ref)) {
            passwordEncoder = new RuntimeBeanReference(ref);
        } else {
            Class beanClass = (Class) ENCODER_CLASSES.get(hash);
            BeanDefinition beanDefinition = new RootBeanDefinition(beanClass);
            if (useBase64) {
                if (beanClass.isAssignableFrom(BaseDigestPasswordEncoder.class)) {
                    beanDefinition.getPropertyValues().addPropertyValue("encodeHashAsBase64", "true");
                } else {
                    logger.warn(ATT_BASE_64 + " isn't compatible with " + OPT_HASH_LDAP_SHA + " and will be ignored");
                }
            }
            passwordEncoder = beanDefinition;
        }

        Element saltSourceElt = DomUtils.getChildElementByTagName(element, Elements.SALT_SOURCE);

        if (saltSourceElt != null) {
            saltSource = new SaltSourceBeanDefinitionParser().parse(saltSourceElt, parserContext);
        }
    }

    public BeanMetadataElement getPasswordEncoder() {
        return passwordEncoder;
    }

    public BeanDefinition getSaltSource() {
        return saltSource;
    }
}
