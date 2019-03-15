/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.authentication;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.encoding.BaseDigestPasswordEncoder;
import org.springframework.security.authentication.encoding.LdapShaPasswordEncoder;
import org.springframework.security.authentication.encoding.Md4PasswordEncoder;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.config.Elements;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Stateful parser for the &lt;password-encoder&gt; element.
 *
 * Will produce a PasswordEncoder and (optionally) a SaltSource.
 *
 * @author Luke Taylor
 */
public class PasswordEncoderParser {
	static final String ATT_REF = "ref";
	public static final String ATT_HASH = "hash";
	static final String ATT_BASE_64 = "base64";
	static final String OPT_HASH_BCRYPT = "bcrypt";
	static final String OPT_HASH_PLAINTEXT = "plaintext";
	static final String OPT_HASH_SHA = "sha";
	static final String OPT_HASH_SHA256 = "sha-256";
	static final String OPT_HASH_MD4 = "md4";
	static final String OPT_HASH_MD5 = "md5";
	static final String OPT_HASH_LDAP_SHA = "{sha}";
	static final String OPT_HASH_LDAP_SSHA = "{ssha}";

	private static final Map<String, Class<?>> ENCODER_CLASSES;

	static {
		ENCODER_CLASSES = new HashMap<String, Class<?>>();
		ENCODER_CLASSES.put(OPT_HASH_PLAINTEXT, PlaintextPasswordEncoder.class);
		ENCODER_CLASSES.put(OPT_HASH_BCRYPT, BCryptPasswordEncoder.class);
		ENCODER_CLASSES.put(OPT_HASH_SHA, ShaPasswordEncoder.class);
		ENCODER_CLASSES.put(OPT_HASH_SHA256, ShaPasswordEncoder.class);
		ENCODER_CLASSES.put(OPT_HASH_MD4, Md4PasswordEncoder.class);
		ENCODER_CLASSES.put(OPT_HASH_MD5, Md5PasswordEncoder.class);
		ENCODER_CLASSES.put(OPT_HASH_LDAP_SHA, LdapShaPasswordEncoder.class);
		ENCODER_CLASSES.put(OPT_HASH_LDAP_SSHA, LdapShaPasswordEncoder.class);
	}

	private static final Log logger = LogFactory.getLog(PasswordEncoderParser.class);

	private BeanMetadataElement passwordEncoder;
	private BeanMetadataElement saltSource;

	public PasswordEncoderParser(Element element, ParserContext parserContext) {
		parse(element, parserContext);
	}

	private void parse(Element element, ParserContext parserContext) {
		String hash = element.getAttribute(ATT_HASH);
		boolean useBase64 = false;

		if (StringUtils.hasText(element.getAttribute(ATT_BASE_64))) {
			useBase64 = Boolean.valueOf(element.getAttribute(ATT_BASE_64)).booleanValue();
		}

		String ref = element.getAttribute(ATT_REF);

		if (StringUtils.hasText(ref)) {
			passwordEncoder = new RuntimeBeanReference(ref);
		}
		else {
			passwordEncoder = createPasswordEncoderBeanDefinition(hash, useBase64);
			((RootBeanDefinition) passwordEncoder).setSource(parserContext
					.extractSource(element));
		}

		Element saltSourceElt = DomUtils.getChildElementByTagName(element,
				Elements.SALT_SOURCE);

		if (saltSourceElt != null) {
			if (OPT_HASH_BCRYPT.equals(hash)) {
				parserContext.getReaderContext().error(
						Elements.SALT_SOURCE + " isn't compatible with bcrypt",
						parserContext.extractSource(saltSourceElt));
			}
			else {
				saltSource = new SaltSourceBeanDefinitionParser().parse(saltSourceElt,
						parserContext);
			}
		}
	}

	public static BeanDefinition createPasswordEncoderBeanDefinition(String hash,
			boolean useBase64) {
		Class<?> beanClass = ENCODER_CLASSES.get(hash);
		BeanDefinitionBuilder beanBldr = BeanDefinitionBuilder
				.rootBeanDefinition(beanClass);

		if (OPT_HASH_SHA256.equals(hash)) {
			beanBldr.addConstructorArgValue(Integer.valueOf(256));
		}

		if (useBase64) {
			if (BaseDigestPasswordEncoder.class.isAssignableFrom(beanClass)) {
				beanBldr.addPropertyValue("encodeHashAsBase64", "true");
			}
			else {
				logger.warn(ATT_BASE_64 + " isn't compatible with " + hash
						+ " and will be ignored");
			}
		}
		return beanBldr.getBeanDefinition();
	}

	public BeanMetadataElement getPasswordEncoder() {
		return passwordEncoder;
	}

	public BeanMetadataElement getSaltSource() {
		return saltSource;
	}
}
