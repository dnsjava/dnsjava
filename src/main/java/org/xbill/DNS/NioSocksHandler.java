package org.xbill.DNS;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

@Getter
@Slf4j
public class NioSocksHandler {
  private static final byte SOCKS5_VERSION = 0x05;
  private static final byte SOCKS5_USER_PWD_AUTH_VERSION = 0x01;
  private static final byte SOCKS5_AUTH_NONE = 0x00;
  private static final byte SOCKS5_AUTH_GSSAPI = 0x01;
  private static final byte SOCKS5_AUTH_USER_PASS = 0x02;
  private static final byte SOCKS5_AUTH_NO_ACCEPTABLE_METHODS = (byte) 0xFF;

  public static final byte SOCKS5_CMD_CONNECT = 0x01;
  public static final byte SOCKS5_CMD_BIND = 0x02;
  public static final byte SOCKS5_CMD_UDP_ASSOCIATE = 0x03;

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

  public NioSocksHandler(InetSocketAddress proxyAddress, InetSocketAddress remoteAddress, InetSocketAddress localAddress, String socks5User, String socks5Password) {
    this.remoteAddress = Objects.requireNonNull(remoteAddress, "remoteAddress must not be null");
    this.localAddress = localAddress;
    this.proxyAddress = Objects.requireNonNull(proxyAddress, "proxyAddress must not be null");
    this.socks5User = socks5User;
    this.socks5Password = socks5Password;
  }

  public NioSocksHandler(InetSocketAddress proxyAddress, InetSocketAddress remoteAddress, InetSocketAddress localAddress) {
    this(proxyAddress, remoteAddress, localAddress, null, null);
  }

  private MethodSelectionRequest getMethodSelectionRequest() {
    return new MethodSelectionRequest((this.socks5User != null && this.socks5Password != null) ? SOCKS5_AUTH_USER_PASS : SOCKS5_AUTH_NONE);
  }

  public CompletableFuture<Void> doAuthHandshake(NioTcpHandler.ChannelState channel, Message query, long endTime) {
    CompletableFuture<Void> authHandshakeF = new CompletableFuture<>();
    CompletableFuture<byte[]> methodSelectionF = new CompletableFuture<>();
    MethodSelectionRequest methodSelectionRequest = getMethodSelectionRequest();
    NioTcpHandler.Transaction methodSelectionTransaction = new NioTcpHandler.Transaction(query, methodSelectionRequest.toBytes(), endTime, channel.getChannel(), methodSelectionF);
    channel.queueTransaction(methodSelectionTransaction);

    methodSelectionF.thenComposeAsync(methodSelectionBytes -> {
      if (methodSelectionBytes.length != 2) {
        authHandshakeF.completeExceptionally(new UnsupportedOperationException("Invalid SOCKS5 method selection response"));
        return null;
      }
      MethodSelectionResponse methodSelectionResponse = new MethodSelectionResponse(methodSelectionBytes);
      if (methodSelectionResponse.getMethod() == SOCKS5_AUTH_NO_ACCEPTABLE_METHODS) {
        authHandshakeF.completeExceptionally(new UnsupportedOperationException("Unsupported SOCKS5 method: " + methodSelectionResponse.getMethod()));
        return null;
      }
      if (methodSelectionResponse.getMethod() == SOCKS5_AUTH_NONE) {
        authHandshakeF.complete(null);
      } else if (methodSelectionResponse.getMethod() == SOCKS5_AUTH_USER_PASS) {
        return handleUserPassAuth(channel, query, endTime, authHandshakeF);
      } else if (methodSelectionResponse.getMethod() == SOCKS5_AUTH_GSSAPI) {
        // TODO: Implement GSSAPI
        authHandshakeF.completeExceptionally(new UnsupportedOperationException("Unsupported SOCKS5 method: " + methodSelectionResponse.getMethod()));
      }
      return null;
    });

    return authHandshakeF;
  }

  private CompletableFuture<Void> handleUserPassAuth(NioTcpHandler.ChannelState channel, Message query, long endTime, CompletableFuture<Void> authHandshakeF) {
    CompletableFuture<byte[]> userPassAuthF = new CompletableFuture<>();
    UserPassAuthRequest userPassAuthRequest = new UserPassAuthRequest(socks5User, socks5Password);
    NioTcpHandler.Transaction userPwdAuthTransaction = new NioTcpHandler.Transaction(query, userPassAuthRequest.toBytes(), endTime, channel.getChannel(), userPassAuthF);
    channel.queueTransaction(userPwdAuthTransaction);

    userPassAuthF.thenComposeAsync(authIn -> {
      UserPwdAuthResponse userPwdAuthResponse = new UserPwdAuthResponse(authIn);
      if (userPwdAuthResponse.getStatus() != SOCKS5_REP_SUCCEEDED) {
        authHandshakeF.completeExceptionally(new UnsupportedOperationException("SOCKS5 user/pwd authentication failed with status: " + userPwdAuthResponse.getStatus()));
      } else {
        authHandshakeF.complete(null);
      }
      return null;
    });

    return authHandshakeF;
  }

  public CompletableFuture<byte[]> doSocks5Request(NioTcpHandler.ChannelState channel, byte socks5Cmd, Message query, long endTime) {
    CompletableFuture<byte[]> cmdHandshakeF = new CompletableFuture<>();
    CompletableFuture<byte[]> commandF = new CompletableFuture<>();
    // For CONNECT, DST.ADDR and DST.PORT are the address and port of the destination server.
    // For UDP ASSOCIATE, DST.ADDR and DST.PORT are the address and port of the UDP client.
    // If DST.ADDR and DST.PORT are set to 0.0.0.0:0, the proxy will accept UDP connections from any source address and port.
    // After the first packet, the source address and port must not change. If they change, the proxy drops the connection and the UDP association.
    InetSocketAddress address = (socks5Cmd == SOCKS5_CMD_CONNECT) ? remoteAddress : new InetSocketAddress("0.0.0.0", 0);
    CmdRequest cmdRequest = new CmdRequest(socks5Cmd, address);
    NioTcpHandler.Transaction commandTransaction = new NioTcpHandler.Transaction(query, cmdRequest.toBytes(), endTime, channel.getChannel(), commandF);
    channel.queueTransaction(commandTransaction);

    commandF.thenComposeAsync(in -> {
      CmdResponse cmdResponse = new CmdResponse(in);
     if (cmdResponse.getReply() != SOCKS5_REP_SUCCEEDED) {
        String errorMessage;
        switch (cmdResponse.getReply()) {
          case SOCKS5_REP_GENERAL_FAILURE:
            errorMessage = "General SOCKS server failure";
            break;
          case SOCKS5_REP_CONNECTION_NOT_ALLOWED:
            errorMessage = "Connection not allowed by ruleset";
            break;
          case SOCKS5_REP_NETWORK_UNREACHABLE:
            errorMessage = "Network unreachable";
            break;
          case SOCKS5_REP_HOST_UNREACHABLE:
            errorMessage = "Host unreachable";
            break;
          case SOCKS5_REP_CONNECTION_REFUSED:
            errorMessage = "Connection refused by destination host";
            break;
          case SOCKS5_REP_TTL_EXPIRED:
            errorMessage = "TTL expired";
            break;
          case SOCKS5_REP_COMMAND_NOT_SUPPORTED:
            errorMessage = "Command not supported";
            break;
          case SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED:
            errorMessage = "Address type not supported";
            break;
          default:
            errorMessage = "Unknown SOCKS5 error with status: " + cmdResponse.getReply();
        }
        cmdHandshakeF.completeExceptionally(new UnsupportedOperationException("SOCKS5 command failed: " + errorMessage));
      } else {
        cmdHandshakeF.complete(in);
      }
      return null;
    });

    return cmdHandshakeF;
  }

  public synchronized CompletableFuture<byte[]> doSocks5Handshake(NioTcpHandler.ChannelState channel, byte socks5Cmd, Message query, long endTime) {
    CompletableFuture<byte[]> socks5HandshakeF = new CompletableFuture<>();
    channel.setSocks5(true);

    CompletableFuture<Void> authHandshakeF = doAuthHandshake(channel, query, endTime);
    authHandshakeF.thenRunAsync(() -> {
      CompletableFuture<byte[]> cmdHandshakeF;
      if (socks5Cmd == SOCKS5_CMD_CONNECT || socks5Cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
        cmdHandshakeF = doSocks5Request(channel, socks5Cmd, query, endTime);
      } else {
        cmdHandshakeF = CompletableFuture.failedFuture(new UnsupportedOperationException("Unsupported SOCKS5 command: " + socks5Cmd));
      }
      cmdHandshakeF.thenComposeAsync(in -> {
        socks5HandshakeF.complete(in);
        return null;
      }).exceptionally(e -> {
        socks5HandshakeF.completeExceptionally(e);
        return null;
      });
    }).exceptionally(e -> {
      socks5HandshakeF.completeExceptionally(e);
      return null;
    });

    return socks5HandshakeF;
  }

  public byte[] addUdpHeader(byte[] data, InetSocketAddress to) {
    ByteBuffer buffer;
    byte addressType;
    byte[] addressBytes;
    if (remoteAddress.getAddress() instanceof Inet4Address) {
      addressType = SOCKS5_ATYP_IPV4;
      addressBytes = remoteAddress.getAddress().getAddress();
      buffer = ByteBuffer.allocate(4 + addressBytes.length + 2 + data.length);
    } else if (remoteAddress.getAddress() instanceof Inet6Address) {
      addressType = SOCKS5_ATYP_IPV6;
      addressBytes = remoteAddress.getAddress().getAddress();
      buffer = ByteBuffer.allocate(4 + addressBytes.length + 2 + data.length);
    } else {
      addressType = SOCKS5_ATYP_DOMAINNAME;
      addressBytes = remoteAddress.getHostName().getBytes(StandardCharsets.UTF_8);
      buffer = ByteBuffer.allocate(4 + 1 + addressBytes.length + 2 + data.length);
    }

    buffer.put((byte) 0x00); // RSV
    buffer.put((byte) 0x00); // RSV
    buffer.put((byte) 0x00); // FRAG
    buffer.put(addressType); // ATYP
    if (addressType == SOCKS5_ATYP_DOMAINNAME) {
      buffer.put((byte) addressBytes.length);
    }
    buffer.put(addressBytes); // DST.ADDR
    buffer.putShort((short) remoteAddress.getPort()); // DST.PORT
    buffer.put(data); // DATA

    return buffer.array();
  }

  public byte[] removeUdpHeader(byte[] in) throws IllegalArgumentException {
    if (in.length < 10) {
      throw new IllegalArgumentException("SOCKS5 UDP response too short");
    }

    int addressType = in[3] & 0xFF;
    int headerLength;
    switch (addressType) {
      case SOCKS5_ATYP_IPV4:
        headerLength = 10;
        break;
      case SOCKS5_ATYP_DOMAINNAME:
        headerLength = 7 + (in[4] & 0xFF);
        break;
      case SOCKS5_ATYP_IPV6:
        headerLength = 22;
        break;
      default:
        throw new IllegalArgumentException("Unsupported address type: " + addressType);
    }

    byte[] out = new byte[in.length - headerLength];
    System.arraycopy(in, headerLength, out, 0, in.length - headerLength);
    return out;
  }

  static class MethodSelectionRequest {
    private final byte version;
    private final byte method;

    public MethodSelectionRequest(byte method) {
      this.version = SOCKS5_VERSION;
      this.method = method;
    }

    public byte[] toBytes() {
      ByteBuffer buffer = ByteBuffer.allocate(3);
      buffer.put(this.version);
      buffer.put((byte) 0x01);
      buffer.put(this.method);
      return buffer.array();
    }
  }

  @Getter
  static class MethodSelectionResponse {
    private final byte version;
    private final byte method;

    public MethodSelectionResponse(byte[] methodSelectionBytes) {
      ByteBuffer buffer = ByteBuffer.wrap(methodSelectionBytes);
      version = buffer.get();
      method = buffer.get();
    }
  }

  static class UserPassAuthRequest {
    private final byte version;
    private final byte usernameLength;
    private final byte[] username;
    private final byte passwordLength;
    private final byte[] password;

    public UserPassAuthRequest(String username, String password) {
      this.version = SOCKS5_USER_PWD_AUTH_VERSION;
      this.username = username.getBytes(StandardCharsets.UTF_8);
      this.usernameLength = (byte) this.username.length;
      this.password = password.getBytes(StandardCharsets.UTF_8);
      this.passwordLength = (byte) this.password.length;
    }

    public byte[] toBytes() {
      ByteBuffer buffer = ByteBuffer.allocate(3 + username.length + password.length);
      buffer.put(this.version);
      buffer.put(this.usernameLength);
      buffer.put(this.username);
      buffer.put(this.passwordLength);
      buffer.put(this.password);
      return buffer.array();
    }
  }

  @Getter
  static class UserPwdAuthResponse {
    private final byte version;
    private final byte status;

    public UserPwdAuthResponse(byte[] userPwdAuthResponseBytes) {
      ByteBuffer buffer = ByteBuffer.wrap(userPwdAuthResponseBytes);
      version = buffer.get();
      status = buffer.get();
    }
  }

  static class CmdRequest {
    private final byte version;
    private final byte command;
    private final byte reserved;
    private final byte addressType;
    private final byte[] addressBytes;
    private final short port;
    private final int bufferSize;

    public CmdRequest(byte command, InetSocketAddress address) {
      this.version = SOCKS5_VERSION;
      this.command = command;
      this.reserved = SOCKS5_RESERVED;
      if (address.getAddress() instanceof Inet4Address) {
        this.addressType = SOCKS5_ATYP_IPV4;
        this.addressBytes = address.getAddress().getAddress();
        this.bufferSize = 10;
      } else if (address.getAddress() instanceof Inet6Address) {
        this.addressType = SOCKS5_ATYP_IPV6;
        this.addressBytes = address.getAddress().getAddress();
        this.bufferSize = 22;
      } else {
        this.addressType = SOCKS5_ATYP_DOMAINNAME;
        this.addressBytes = address.getHostName().getBytes(StandardCharsets.UTF_8);
        this.bufferSize = 6 + 1 + addressBytes.length;
      }
      this.port = (short) address.getPort();
    }

    public byte[] toBytes() {
      ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
      buffer.put(this.version);
      buffer.put(this.command);
      buffer.put(this.reserved);
      buffer.put(this.addressType);
      if (addressType == SOCKS5_ATYP_DOMAINNAME) {
        buffer.put((byte) addressBytes.length);
      }
      buffer.put(this.addressBytes);
      buffer.putShort(this.port);
      return buffer.array();
    }
  }

  @Getter
  static class CmdResponse {
    private final byte version;
    private final byte reply;
    private final byte reserved;
    private final byte addressType;
    private final byte[] address;
    private final int port;

    public CmdResponse(byte[] commandResponseBytes) {
      ByteBuffer buffer = ByteBuffer.wrap(commandResponseBytes);
      this.version = buffer.get();
      this.reply = buffer.get();
      this.reserved = buffer.get();
      this.addressType = buffer.get();

      if (addressType == SOCKS5_ATYP_IPV4) {
        this.address = new byte[4];
      } else if (addressType == SOCKS5_ATYP_IPV6) {
        this.address = new byte[16];
      } else if (addressType == SOCKS5_ATYP_DOMAINNAME) {
        int domainLength = buffer.get() & 0xFF;
        this.address = new byte[domainLength];
      } else {
        throw new IllegalArgumentException("Unsupported address type: " + addressType);
      }

      buffer.get(this.address);
      this.port = Short.toUnsignedInt(buffer.getShort());
    }
  }
}
