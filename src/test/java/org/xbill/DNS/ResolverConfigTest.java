package org.xbill.DNS;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

class ResolverConfigTest {

	@AfterEach
	void tearDown() {
		ResolverConfig.refresh();
	}

	@Test
	void findProperty_Success() {
		String[] dnsServers = { "server1", "server2" };
		// intentionally adding duplicate search entries for testing
		String[] dnsSearch = { "dnsjava.org", "example.com",
			"dnsjava.org" };
		Name[] searchPath = Arrays.stream(dnsSearch)
			.map(s -> Name.fromConstantString(s, Name.root))
			.toArray(Name[]::new);
		System.setProperty(ResolverConfig.DNS_SERVER_PROP,
			String.join(",", dnsServers));
		System.setProperty(ResolverConfig.DNS_SEARCH_PROP,
			String.join(",", dnsSearch));
		try {
			ResolverConfig.refresh();
			ResolverConfig rc = ResolverConfig.getCurrentConfig();
			assertTrue(rc.findProperty());
			assertEquals("server1", rc.server());
			assertEquals(2, rc.servers().length);
			// any duplicate suffixes should be excluded
			assertEquals(2, rc.searchPath().length);
			assertEquals(searchPath[0], rc.searchPath()[0]);
			assertEquals(searchPath[1], rc.searchPath()[1]);
		} finally {
			System.clearProperty(ResolverConfig.DNS_SERVER_PROP);
			System.clearProperty(ResolverConfig.DNS_SEARCH_PROP);
		}
	}

	@Test
	@EnabledOnOs({OS.WINDOWS})
	void findNT_Windows() {
		assertTrue(ResolverConfig.getCurrentConfig().findWin());
	}

	@Test
	@DisabledOnOs({OS.WINDOWS})
	void findNT_NotWindows() {
		assertFalse(ResolverConfig.getCurrentConfig().findWin());
	}

	@Test
	@EnabledOnOs({OS.LINUX, OS.MAC, OS.AIX, OS.SOLARIS})
	void findUnix() {
		assertTrue(ResolverConfig.getCurrentConfig().findUnix());
	}

	@Test
	void resolvConfLoaded() throws URISyntaxException {
		assertTrue(ResolverConfig.getCurrentConfig()
			.findResolvConf(Paths.get(getClass()
				.getResource("/test_loaded_resolv.conf")
				.toURI()).toString()));
		assertEquals(5, ResolverConfig.getCurrentConfig().ndots());
	}

	@Test
	void findNetware() {
		assumeFalse(ResolverConfig.getCurrentConfig().findNetware());
	}

	@Test
	void findAndroid() {
		assumeFalse(ResolverConfig.getCurrentConfig().findAndroid());
	}
}
