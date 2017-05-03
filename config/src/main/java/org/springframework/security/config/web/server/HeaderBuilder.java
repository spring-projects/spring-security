/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.web.server;

import org.springframework.security.web.server.header.CacheControlHttpHeadersWriter;
import org.springframework.security.web.server.header.CompositeHttpHeadersWriter;
import org.springframework.security.web.server.header.ContentTypeOptionsHttpHeadersWriter;
import org.springframework.security.web.server.header.HttpHeaderWriterWebFilter;
import org.springframework.security.web.server.header.HttpHeadersWriter;
import org.springframework.security.web.server.header.StrictTransportSecurityHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsHttpHeadersWriter;
import org.springframework.security.web.server.header.XXssProtectionHttpHeadersWriter;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class HeaderBuilder {
	private final List<HttpHeadersWriter> writers;

	private CacheControlHttpHeadersWriter cacheControl = new CacheControlHttpHeadersWriter();

	private ContentTypeOptionsHttpHeadersWriter contentTypeOptions = new ContentTypeOptionsHttpHeadersWriter();

	private StrictTransportSecurityHttpHeadersWriter hsts = new StrictTransportSecurityHttpHeadersWriter();

	private XFrameOptionsHttpHeadersWriter frameOptions = new XFrameOptionsHttpHeadersWriter();

	private XXssProtectionHttpHeadersWriter xss = new XXssProtectionHttpHeadersWriter();

	public HeaderBuilder() {
		this.writers = new ArrayList<>(Arrays.asList(cacheControl, contentTypeOptions, hsts, frameOptions, xss));
	}

	public CacheSpec cache() {
		return new CacheSpec();
	}

	public ContentTypeOptionsSpec contentTypeOptions() {
		return new ContentTypeOptionsSpec();
	}

	public FrameOptionsSpec frameOptions() {
		return new FrameOptionsSpec();
	}

	public HstsSpec hsts() {
		return new HstsSpec();
	}

	public HttpHeaderWriterWebFilter build() {
		HttpHeadersWriter writer = new CompositeHttpHeadersWriter(writers);
		return new HttpHeaderWriterWebFilter(writer);
	}

	public XssProtectionSpec xssProtection() {
		return new XssProtectionSpec();
	}

	public class CacheSpec {
		public void disable() {
			writers.remove(cacheControl);
		}

		private CacheSpec() {}
	}

	public class ContentTypeOptionsSpec {
		public void disable() {
			writers.remove(contentTypeOptions);
		}

		private ContentTypeOptionsSpec() {}
	}

	public class FrameOptionsSpec {
		public void mode(XFrameOptionsHttpHeadersWriter.Mode mode) {
			frameOptions.setMode(mode);
		}
		public void disable() {
			writers.remove(frameOptions);
		}

		private FrameOptionsSpec() {}
	}

	public class HstsSpec {
		public void maxAge(Duration maxAge) {
			hsts.setMaxAge(maxAge);
		}

		public void includeSubdomains(boolean includeSubDomains) {
			hsts.setIncludeSubDomains(includeSubDomains);
		}

		public void disable() {
			writers.remove(hsts);
		}

		private HstsSpec() {}
	}

	public class XssProtectionSpec {
		public void disable() {
			writers.remove(xss);
		}

		private XssProtectionSpec() {}
	}
}
