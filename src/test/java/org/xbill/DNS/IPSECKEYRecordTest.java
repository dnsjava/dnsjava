package org.xbill.DNS;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import org.junit.jupiter.api.Test;

class IPSECKEYRecordTest {

  Name n = Name.fromConstantString("my.name.");

  @Test
  void ctor_0arg() {
    IPSECKEYRecord record = new IPSECKEYRecord();
    assertEquals(0, record.getPrecedence());
    assertEquals(0, record.getGatewayType());
    assertEquals(0, record.getAlgorithmType());
    assertNull(record.getGateway());
    assertNull(record.getKey());
  }

  @Test
  void ctor_8arg() {
    IPSECKEYRecord record =
        new IPSECKEYRecord(
            n,
            DClass.IN,
            0,
            1,
            IPSECKEYRecord.Gateway.Name,
            IPSECKEYRecord.Algorithm.DSA,
            n,
            "".getBytes());
    assertEquals(1, record.getPrecedence());
    assertEquals(IPSECKEYRecord.Gateway.Name, record.getGatewayType());
    assertEquals(IPSECKEYRecord.Algorithm.DSA, record.getAlgorithmType());
    assertEquals(n, record.getGateway());
    assertEquals(0, record.getKey().length);
  }

  @Test
  void rdataFromString() throws IOException {
    Tokenizer t = new Tokenizer("10 0 2 . CAFEBABE");
    IPSECKEYRecord record = new IPSECKEYRecord();
    record.rdataFromString(t, null);
    assertEquals(10, record.getPrecedence());
    assertEquals(IPSECKEYRecord.Gateway.None, record.getGatewayType());
    assertEquals(IPSECKEYRecord.Algorithm.RSA, record.getAlgorithmType());
    assertNull(record.getGateway());
    assertEquals(6, record.getKey().length);
    record = new IPSECKEYRecord();
    t = new Tokenizer("( 10 1 2 192.0.2.3 CAFEBABE )");
    record.rdataFromString(t, null);
    assertEquals(1, record.getGatewayType());
    assertTrue(record.getGateway() instanceof InetAddress);
    record = new IPSECKEYRecord();
    t = new Tokenizer("10 2 2 2001:0DB8:0:8002::2000:1 CAFEBABE");
    record.rdataFromString(t, null);
    assertEquals(2, record.getGatewayType());
    assertTrue(record.getGateway() instanceof InetAddress);
    record = new IPSECKEYRecord();
    t = new Tokenizer("10 3 2 mygateway.example.com. CAFEBABE");
    record.rdataFromString(t, null);
    assertEquals(3, record.getGatewayType());
    assertEquals(Name.fromConstantString("mygateway.example.com."), record.getGateway());
  }
}
