package org.xbill.DNS;

import lombok.Getter;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Objects;

@Getter
public class Socks5Proxy {
  private static final byte SOCKS5_VERSION = 0x05;
  private static final byte SOCKS5_USER_PWD_AUTH_VERSION = 0x01;
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
  private final String socks5User;
  private final String socks5Password;

  public Socks5Proxy(InetSocketAddress proxyAddress, InetSocketAddress remoteAddress, InetSocketAddress localAddress, String socks5User, String socks5Password) {
    this.remoteAddress = Objects.requireNonNull(remoteAddress, "remoteAddress must not be null");
    this.localAddress = Objects.requireNonNull(localAddress, "localAddress must not be null");
    this.proxyAddress = Objects.requireNonNull(proxyAddress, "proxyAddress must not be null");
    this.socks5User = socks5User;
    this.socks5Password = socks5Password;
  }

  public Socks5Proxy(InetSocketAddress proxyAddress, InetSocketAddress remoteAddress, InetSocketAddress localAddress) {
    this(proxyAddress, remoteAddress, localAddress, null, null);
  }

  private void writeToChannel(SocketChannel c, ByteBuffer buffer) {
    try {
      c.write(buffer);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to write to TCP channel", e);
    }
  }

  private void readFromChannel(SocketChannel c, ByteBuffer buffer) {
    try {
      c.read(buffer);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to read from TCP channel", e);
    }
  }

  public byte socks5MethodSelection(SocketChannel c) {
    ByteBuffer buffer = ByteBuffer.allocate(3);
    buffer.put(SOCKS5_VERSION);
    buffer.put((byte) 1);
    buffer.put((this.socks5User != null && this.socks5Password != null) ? SOCKS5_AUTH_USER_PASS : SOCKS5_AUTH_NONE);
    buffer.flip();

    writeToChannel(c, buffer);
    buffer.clear();

    readFromChannel(c, buffer);
    buffer.flip();

    if (buffer.get() != SOCKS5_VERSION) {
      throw new IllegalStateException("Invalid SOCKS5 version");
    }

    byte method = buffer.get();
    if (method == SOCKS5_AUTH_NO_ACCEPTABLE_METHODS) {
      throw new IllegalStateException("No acceptable authentication methods");
    }
    return method;
  }

  public void socks5UserPwdAuthExchange(SocketChannel c) {
    ByteBuffer buffer = ByteBuffer.allocate(520);
    buffer.put(SOCKS5_USER_PWD_AUTH_VERSION);
    buffer.put((byte) this.socks5User.length());
    buffer.put(this.socks5User.getBytes());
    buffer.put((byte) this.socks5Password.length());
    buffer.put(this.socks5Password.getBytes());
    buffer.flip();

    writeToChannel(c, buffer);
    buffer.clear();

    readFromChannel(c, buffer);
    buffer.flip();

    if (!buffer.hasRemaining()) {
      throw new IllegalStateException("Authentication failed. No data received from server");
    }

    if (buffer.get() != SOCKS5_USER_PWD_AUTH_VERSION) {
      throw new IllegalStateException("Invalid user/pwd auth subnegotiation version");
    }

    byte reply = buffer.get();
    if (reply != SOCKS5_REP_SUCCEEDED) {
      throw new IllegalStateException("Authentication failed with status " + reply);
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

    writeToChannel(c, buffer);
    buffer.clear();

    readFromChannel(c, buffer);
    buffer.flip();

    if (!buffer.hasRemaining()) {
      throw new IllegalStateException("SOCKS5 handshake failed. No data received from server");
    }

    if (buffer.get() != SOCKS5_VERSION) {
      throw new IllegalStateException("Invalid SOCKS5 version");
    }

    byte reply = buffer.get();
    if (reply != SOCKS5_REP_SUCCEEDED) {
      throw new IllegalStateException("Connection to remote server failed: " + reply);
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

    writeToChannel(c, buffer);
    buffer.clear();

    readFromChannel(c, buffer);
    buffer.flip();

    if (!buffer.hasRemaining()) {
      throw new IllegalStateException("SOCKS5 udp associate exchange failed. No data received from server");
    }

    if (buffer.get() != SOCKS5_VERSION) {
      throw new IllegalStateException("Invalid SOCKS5 version");
    }

    byte reply = buffer.get();
    if (reply != SOCKS5_REP_SUCCEEDED) {
      throw new IllegalStateException("UDP association failed: " + reply);
    }

    buffer.get(); // skip RSV byte

    byte atyp = buffer.get();
    if (atyp != SOCKS5_ATYP_IPV4) {
      throw new IllegalStateException("Invalid address type");
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

  public void socks5TcpHandshake(SocketChannel c, InetSocketAddress remote) {
    byte method = this.socks5MethodSelection(c);
    if (method == SOCKS5_AUTH_USER_PASS) {
      this.socks5UserPwdAuthExchange(c);
    }
    this.socks5HeaderExchange(c, remote);
  }

  public InetSocketAddress socks5UdpAssociateHandshake(SocketChannel c) throws UnknownHostException {
    byte method = this.socks5MethodSelection(c);
    if (method == SOCKS5_AUTH_USER_PASS) {
      if (this.socks5User == null || this.socks5Password == null) {
        throw new IllegalStateException("No user or password provided");
      }
      this.socks5UserPwdAuthExchange(c);
    }
    return this.socks5UdpAssociateExchange(c);
  }
}
