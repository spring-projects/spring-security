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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Stateful parser for the &lt;password-encoder&gt; element.
 *
 * @author Luke Taylor
 */
public class PasswordEncoderParser {
	static final String ATT_REF = "ref";
	public static final String ATT_HASH = "hash";
	static final String ATT_BASE_64 = "base64";
	static final String OPT_HASH_BCRYPT = "bcrypt";

	private static final Map<String, Class<?>> ENCODER_CLASSES;

	static {
		ENCODER_CLASSES = new HashMap<>();
		ENCODER_CLASSES.put(OPT_HASH_BCRYPT, BCryptPasswordEncoder.class);
	}

	private static final Log logger = LogFactory.getLog(PasswordEncoderParser.class);

	private BeanMetadataElement passwordEncoder;

	public PasswordEncoderParser(Element element, ParserContext parserContext) {
		parse(element, parserContext);
	}

	private void parse(Element element, ParserContext parserContext) {
		if (element == null) {
			if (parserContext.getRegistry().containsBeanDefinition("passwordEncoder")) {
				this.passwordEncoder = parserContext.getRegistry().getBeanDefinition("passwordEncoder");
			}
			return;
		}
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
	}

	public static BeanDefinition createPasswordEncoderBeanDefinition(String hash,
			boolean useBase64) {
		Class<?> beanClass = ENCODER_CLASSES.get(hash);
		BeanDefinitionBuilder beanBldr = BeanDefinitionBuilder
				.rootBeanDefinition(beanClass);
		return beanBldr.getBeanDefinition();
	}

	public BeanMetadataElement getPasswordEncoder() {
		return passwordEncoder;
	}
}
