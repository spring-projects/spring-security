package org.springframework.security.web.util.matcher;

import java.net.InetAddress;
import java.util.List;

final class AllowedInetAddressFilter implements InetAddressFilter {

	private final List<IpAddressMatcher> allowList;

	public AllowedInetAddressFilter(List<String> allowList) {
		this.allowList = allowList.stream().map(IpAddressMatcher::new).toList();
	}

	@Override
	public boolean filter(InetAddress address) {
		if (this.allowList.isEmpty()) {
			return true;
		}
		for (IpAddressMatcher matcher : this.allowList) {
			if (matcher.matches(address)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String toString() {
		return "AllowedInetAddressVerifier[\"" + this.allowList + "\"]";
	}

}
