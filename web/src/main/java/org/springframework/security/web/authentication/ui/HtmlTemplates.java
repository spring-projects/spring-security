/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.authentication.ui;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;

/**
 * Render HTML templates using string substitution. Intended for internal use. Variables
 * can be templated using double curly-braces: {@code {{name}}}.
 *
 * @author Daniel Garnier-Moiroux
 * @since 6.4
 */
final class HtmlTemplates {

	private HtmlTemplates() {
	}

	static Builder fromTemplate(String template) {
		return new Builder(template);
	}

	static final class Builder {

		private final String template;

		private final Map<String, String> values = new HashMap<>();

		private Builder(String template) {
			this.template = template;
		}

		/**
		 * HTML-escape, and inject value {@code value} in every {@code {{key}}}
		 * placeholder.
		 * @param key the placeholder name
		 * @param value the value to inject
		 * @return this instance for further templating
		 */
		Builder withValue(String key, String value) {
			this.values.put(key, HtmlUtils.htmlEscape(value));
			return this;
		}

		/**
		 * Inject value {@code value} in every {@code {{key}}} placeholder without
		 * HTML-escaping. Useful for injecting "sub-templates".
		 * @param key the placeholder name
		 * @param value the value to inject
		 * @return this instance for further templating
		 */
		Builder withRawHtml(String key, String value) {
			if (!value.isEmpty() && value.charAt(value.length() - 1) == '\n') {
				value = value.substring(0, value.length() - 1);
			}
			this.values.put(key, value);
			return this;
		}

		/**
		 * Render the template. All placeholders MUST have a corresponding value. If a
		 * placeholder does not have a corresponding value, throws
		 * {@link IllegalStateException}.
		 * @return the rendered template
		 */
		String render() {
			String template = this.template;
			for (String key : this.values.keySet()) {
				String pattern = Pattern.quote("{{" + key + "}}");
				template = template.replaceAll(pattern, this.values.get(key));
			}

			String unusedPlaceholders = Pattern.compile("\\{\\{([a-zA-Z0-9]+)}}")
				.matcher(template)
				.results()
				.map((result) -> result.group(1))
				.collect(Collectors.joining(", "));
			if (StringUtils.hasLength(unusedPlaceholders)) {
				throw new IllegalStateException("Unused placeholders in template: [%s]".formatted(unusedPlaceholders));
			}

			return template;
		}

	}

}
