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
package com.google.springframework.security.web.ssrf;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class BasicSSRFProtectionFilter implements SsrfProtectionFilter {

	public enum FilterMode {
		ALLOW_INTERNAL_BLOCK_EXTERNAL,
		BLOCK_INTERNAL_ALLOW_EXTERNAL

	}

	private FilterMode mode;


	public BasicSSRFProtectionFilter(FilterMode mode) {
		this.mode = mode;
	}

	@Override
	public InetAddress[] filter(InetAddress[] addresses) throws HostBlockedException {

		List<InetAddress> result = new ArrayList<>(addresses.length);

		for (InetAddress addr : addresses) {
			boolean isInternal = FilterUtils.isInternalIp(addr);
			boolean shouldAllow = switch (mode) {
				case ALLOW_INTERNAL_BLOCK_EXTERNAL -> isInternal;
				case BLOCK_INTERNAL_ALLOW_EXTERNAL -> !isInternal;
			};
			if (shouldAllow) {
				result.add(addr);
			}

		}

		if (result.size() == 0) {
			String addrFmt = Arrays.stream(addresses).map(a -> a.toString()).collect(Collectors.joining(", "));
			throw new HostBlockedException(
					"The following address(es) were blocked due to violating " + mode.name() + " policy: " + addrFmt);
		}

		return result.toArray(new InetAddress[]{});
	}


}
