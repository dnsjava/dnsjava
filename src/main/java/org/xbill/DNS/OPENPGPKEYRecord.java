package org.xbill.DNS;

import java.io.IOException;
import org.xbill.DNS.utils.base64;

/**
 * OPENPGPKEY Record - Stores an OpenPGP certificate associated with a name.
 *
 * @author Brian Wellington
 * @author Valentin Hauner
 * @see <a href="https://tools.ietf.org/html/rfc7929">RFC 7929: DNS-Based Authentication of Named
 *     Entities (DANE) Bindings for OpenPGP</a>
 */
public class OPENPGPKEYRecord extends Record {
  private byte[] cert;

  OPENPGPKEYRecord() {}

  /**
   * Creates an OPENPGPKEY Record from the given data
   *
   * @param cert Binary data representing the certificate
   */
  public OPENPGPKEYRecord(Name name, int dclass, long ttl, byte[] cert) {
    super(name, Type.OPENPGPKEY, dclass, ttl);
    this.cert = cert;
  }

  @Override
  protected void rrFromWire(DNSInput in) {
    cert = in.readByteArray();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    cert = st.getBase64();
  }

  /** Converts rdata to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    if (cert != null) {
      if (Options.check("multiline")) {
        sb.append("(\n");
        sb.append(base64.formatString(cert, 64, "\t", true));
      } else {
        sb.append(base64.toString(cert));
      }
    }
    return sb.toString();
  }

  /** Returns the binary representation of the certificate */
  public byte[] getCert() {
    return cert;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeByteArray(cert);
  }
}
