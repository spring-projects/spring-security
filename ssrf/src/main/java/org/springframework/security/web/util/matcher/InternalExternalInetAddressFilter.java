package org.springframework.security.web.util.matcher;

import java.net.InetAddress;

final class InternalExternalInetAddressFilter implements InetAddressFilter {

	private final boolean blockExternal;

	InternalExternalInetAddressFilter(boolean blockExternal) {
		this.blockExternal = blockExternal;
	}

	public boolean shouldBlockExternal() {
		return this.blockExternal;
	}

	@Override
	public boolean filter(InetAddress address) {
		return (this.blockExternal == isLocal(address));
	}

	private static boolean isLocal(InetAddress address) {
		if (address.isLoopbackAddress()) {
			return true;
		}

		byte[] rawAddress = address.getAddress();

		// there is sadly no Stream support for byte arrays
		int[] iAddr = new int[rawAddress.length];
		for (int i = 0; i < rawAddress.length; i++) {
			iAddr[i] = Byte.toUnsignedInt(rawAddress[i]);
		}

		// Ignoring Multicast addresses
		if (address.getAddress().length == 4) {
			// IPv4 filtering
			// 10.x.x.x , 192.168.x.x , 172.16.x.x
			if (iAddr[0] == 10 ||
					(iAddr[0] == 192 && iAddr[1] == 168) ||
					(iAddr[0] == 172 && iAddr[1] == 16)) {
				return true;
			}

		}
		else if (address.getAddress().length == 16) {
			// IPv6, check for Unique Local Addresses
			if (iAddr[0] == 0xfc || iAddr[0] == 0xfd) {
				return true;
			}

			// IPv4/IPv6 translation, 64:ff9b
			if (iAddr[0] == 0x00 && iAddr[1] == 0x64 && iAddr[2] == 0xff && iAddr[3] == 0x9b) {
				int[] ipv4Part = new int[] {iAddr[12], iAddr[13], iAddr[14], iAddr[15]};
				// same check as above plus a check for loopback
				if (ipv4Part[0] == 10 || ipv4Part[0] == 127 ||
						(ipv4Part[0] == 192 && ipv4Part[1] == 168) ||
						(ipv4Part[0] == 172 && ipv4Part[1] == 16)) {
					return true;
				}
			}
		}

		return false;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " (" + (this.blockExternal ? "blockExternal" : "blockInternal") + ")";
	}

}
