package org.xbill.DNS;

import lombok.Getter;

import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

@Getter
public class Socks5Proxy {
  private static final byte SOCKS5_VERSION = 0x05;

  private static final byte SOCKS5_AUTH_NONE = 0x00;
  private static final byte SOCKS5_AUTH_GSSAPI = 0x01;
  private static final byte SOCKS5_AUTH_USER_PASS = 0x02;
  private static final byte SOCKS5_AUTH_NO_ACCEPTABLE_METHODS = (byte) 0xFF;

  private static final byte SOCKS5_CMD_CONNECT = 0x01;
  private static final byte SOCKS5_CMD_BIND = 0x02;
  private static final byte SOCKS5_CMD_UDP_ASSOCIATE = 0x03;

  private static final byte SOCKS5_ATYP_IPV4 = 0x01;
  private static final byte SOCKS5_ATYP_DOMAINNAME = 0x03;
  private static final byte SOCKS5_ATYP_IPV6 = 0x04;

  private static final byte SOCKS5_REP_SUCCEEDED = 0x00;
  private static final byte SOCKS5_REP_GENERAL_FAILURE = 0x01;
  private static final byte SOCKS5_REP_CONNECTION_NOT_ALLOWED = 0x02;
  private static final byte SOCKS5_REP_NETWORK_UNREACHABLE = 0x03;
  private static final byte SOCKS5_REP_HOST_UNREACHABLE = 0x04;
  private static final byte SOCKS5_REP_CONNECTION_REFUSED = 0x05;
  private static final byte SOCKS5_REP_TTL_EXPIRED = 0x06;
  private static final byte SOCKS5_REP_COMMAND_NOT_SUPPORTED = 0x07;
  private static final byte SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;

  private static final byte SOCKS5_RESERVED = 0x00;

  private final InetSocketAddress remoteAddress;
  private final InetSocketAddress localAddress;
  private final InetSocketAddress proxyAddress;


  public Socks5Proxy(InetSocketAddress proxyAddress, InetSocketAddress remoteAddress, InetSocketAddress localAddress) {
    this.remoteAddress = remoteAddress;
    this.localAddress = localAddress;
    this.proxyAddress = proxyAddress;
  }

  public void socks5MethodSelection(SocketChannel c) {
    ByteBuffer buffer = ByteBuffer.allocate(3);
    buffer.put(SOCKS5_VERSION);
    buffer.put((byte) 1);
    buffer.put(SOCKS5_AUTH_NONE);
    buffer.flip();

    try {
      c.write(buffer);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to write to TCP channel", e);
    }

    buffer.clear();

    try {
      c.read(buffer);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to read from TCP channel", e);
    }

    buffer.flip();
    if (buffer.get() != SOCKS5_VERSION) {
      throw new IllegalArgumentException("Invalid version");
    }

    if (buffer.get() == SOCKS5_AUTH_NO_ACCEPTABLE_METHODS) {
      throw new IllegalArgumentException("No acceptable methods");
    }
  }

  public void socks5HeaderExchange(SocketChannel c, InetSocketAddress remote) {
    ByteBuffer buffer = ByteBuffer.allocate(10);
    buffer.put(SOCKS5_VERSION);
    buffer.put(SOCKS5_CMD_CONNECT);
    buffer.put(SOCKS5_RESERVED);
    buffer.put(SOCKS5_ATYP_IPV4);
    buffer.put(remote.getAddress().getAddress());
    buffer.putShort((short) remote.getPort());
    buffer.flip();

    try {
      c.write(buffer);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to write to TCP channel", e);
    }
    buffer.clear();

    try {
      c.read(buffer);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to read from TCP channel", e);
    }
    buffer.flip();

    if (buffer.get() != SOCKS5_VERSION) {
      throw new IllegalArgumentException("Invalid version");
    }

    byte reply = buffer.get();
    if (reply != SOCKS5_REP_SUCCEEDED) {
      throw new IllegalArgumentException("Failed to connect to remote server: " + reply);
    }
  }

  public InetSocketAddress socks5UdpAssociateExchange(SocketChannel c) {
    ByteBuffer buffer = ByteBuffer.allocate(10);
    buffer.put(SOCKS5_VERSION);
    buffer.put(SOCKS5_CMD_UDP_ASSOCIATE);
    buffer.put(SOCKS5_RESERVED);
    buffer.put(SOCKS5_ATYP_IPV4);
    buffer.put(new byte[] {0, 0, 0, 0});
    buffer.putShort((short) 0x00);
    buffer.flip();

    try {
      c.write(buffer);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to write to TCP channel", e);
    }
    buffer.clear();

    try {
      c.read(buffer);
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to read from TCP channel", e);
    }
    buffer.flip();

    if (buffer.get() != SOCKS5_VERSION) {
      throw new IllegalArgumentException("Invalid version");
    }

    byte reply = buffer.get();
    if (reply != SOCKS5_REP_SUCCEEDED) {
      throw new IllegalArgumentException("Failed to connect to remote server: " + reply);
    }

    buffer.get(); // skip RSV byte

    byte atyp = buffer.get();
    if (atyp != SOCKS5_ATYP_IPV4) {
      throw new IllegalArgumentException("Invalid address type");
    }

    byte[] addr = new byte[4];
    buffer.get(addr);
    int port = buffer.getShort() & 0xFFFF;
    return new InetSocketAddress(this.getProxyAddress().getAddress(), port);
  }

  public byte[] addUdpHeader(byte[] in, InetSocketAddress to) {
    ByteBuffer buffer = ByteBuffer.allocate(in.length + 10);
    buffer.put(SOCKS5_VERSION);
    buffer.put(SOCKS5_RESERVED);
    buffer.put(SOCKS5_RESERVED);
    buffer.put(SOCKS5_ATYP_IPV4);
    buffer.put(to.getAddress().getAddress());
    buffer.putShort((short) to.getPort());
    buffer.put(in);

    return buffer.array();
  }

  public byte[] removeUdpHeader(byte[] in) {
    byte[] out = new byte[in.length - 10];
    System.arraycopy(in, 10, out, 0, in.length - 10);
    return out;
  }

  public void socks5TcpHandshake(
    SocketChannel c, InetSocketAddress remote) {
    this.socks5MethodSelection(c);
    this.socks5HeaderExchange(c, remote);
  }

  public InetSocketAddress socks5UdpAssociateHandshake(
    SocketChannel c
    ) throws UnknownHostException {
    this.socks5MethodSelection(c);
    return this.socks5UdpAssociateExchange(c);
  }
}
