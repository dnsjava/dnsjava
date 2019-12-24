// SPDX-License-Identifier: BSD-2-Clause
package org.xbill.DNS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.xbill.DNS.DNSSEC.Algorithm;

/**
 * The EDNS0 Option for Signaling Cryptographic Algorithm Understanding in DNS Security Extensions
 * (DNSSEC), RFC 6975.
 */
public class DnssecAlgorithmOption extends EDNSOption {
  private List<Integer> algCodes;

  private DnssecAlgorithmOption(int code) {
    super(code);
    switch (code) {
      case Code.DAU:
      case Code.DHU:
      case Code.N3U:
        break;
      default:
        throw new IllegalArgumentException("Invalid option code, must be one of DAU, DHU, N3U");
    }
    algCodes = new ArrayList<>();
  }

  public DnssecAlgorithmOption(int code, List<Integer> algCodes) {
    this(code);
    this.algCodes.addAll(algCodes);
  }

  public DnssecAlgorithmOption(int code, int... algCodes) {
    this(code);
    if (algCodes != null) {
      for (int algCode : algCodes) {
        this.algCodes.add(algCode);
      }
    }
  }

  public List<Integer> getAlgorithms() {
    return Collections.unmodifiableList(algCodes);
  }

  @Override
  void optionFromWire(DNSInput in) throws IOException {
    algCodes.clear();
    while (in.remaining() > 0) {
      algCodes.add(in.readU8());
    }
  }

  @Override
  void optionToWire(DNSOutput out) {
    algCodes.forEach(out::writeU8);
  }

  @Override
  String optionToString() {
    return Code.string(getCode())
        + ": ["
        + algCodes.stream().map(Algorithm::string).collect(Collectors.joining(", "))
        + "]";
  }
}
