// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS.dnssec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

class TestTrustAnchorLoading extends TestBase {
  @Test
  void testLoadRootTrustAnchors() {
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.IN)).isNotNull();
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.CH)).isNull();
  }

  @Test
  void testLoadRootTrustAnchorsFromFile() throws IOException {
    resolver.getTrustAnchors().clear();
    Properties config = new Properties();
    config.put("dnsjava.dnssec.trust_anchor_file", "./src/test/resources/trust_anchors");
    resolver.init(config);
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.IN)).isNotNull();
  }

  @Test
  void testInitializingWithEmptyConfigDoesNotFail() throws IOException {
    resolver.getTrustAnchors().clear();
    Properties config = new Properties();
    resolver.init(config);
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.IN)).isNull();
  }

  @Test
  void testInitializingWithNonExistingFileThrows() {
    resolver.getTrustAnchors().clear();
    Properties config = new Properties();
    config.put("dnsjava.dnssec.trust_anchor_file", "xyz");
    assertThatExceptionOfType(IOException.class).isThrownBy(() -> resolver.init(config));
  }

  @Test
  void testLoadRootTrustAnchorWithDNSKEY() throws IOException {
    Message keys = resolver.send(createMessage("./DNSKEY"));
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    OutputStreamWriter osw = new OutputStreamWriter(bos);
    for (RRset set : keys.getSectionRRsets(Section.ANSWER)) {
      if (set.getType() == Type.DNSKEY) {
        for (Record r : set.rrs()) {
          osw.write(r.toString());
          osw.write('\n');
        }
      }
    }

    osw.close();

    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(new ByteArrayInputStream(bos.toByteArray()));
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.IN)).isNotNull();

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must be set").isTrue();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isNull();
    assertEde(-1, response);
  }

  @Test
  void testLoadRootTrustAnchorWithInvalidDNSKEY() throws IOException {
    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_dnskey_invalid"));
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.IN)).isNotNull();

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response))
        .isEqualTo("validate.bogus.badkey:.:dnskey.no_ds_alg_match:.:RSASHA256");
    assertEde(ExtendedErrorCodeOption.DNSKEY_MISSING, response);
  }

  @Test
  void testLoadRootTrustAnchorWithInvalidDS() throws IOException {
    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_invalid"));
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.IN)).isNotNull();

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.SERVFAIL, response.getRcode());
    assertThat(getReason(response)).isEqualTo("validate.bogus.badkey:.:dnskey.no_ds_match");
    assertEde(ExtendedErrorCodeOption.DNSSEC_BOGUS, response);
  }

  @Test
  void testLoadRootTrustAnchorsAlongWithGarbage() throws IOException {
    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_test"));
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.IN)).isNotNull();
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.CH)).isNotNull();
  }

  @Test
  void testLoadEmptyTrustAnchors() throws IOException {
    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_empty"));
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.IN)).isNull();
  }

  @Test
  void testInsecureWithEmptyTrustAnchor() throws IOException {
    resolver.getTrustAnchors().clear();
    resolver.loadTrustAnchors(getClass().getResourceAsStream("/trust_anchors_empty"));
    assertThat(resolver.getTrustAnchors().find(Name.root, DClass.IN)).isNull();

    Message response = resolver.send(createMessage("www.ingotronic.ch./A"));
    assertThat(response.getHeader().getFlag(Flags.AD)).as("AD flag must not be set").isFalse();
    assertRCode(Rcode.NOERROR, response.getRcode());
    assertThat(getReason(response)).isEqualTo("validate.insecure");
    assertEde(-1, response);
  }
}
