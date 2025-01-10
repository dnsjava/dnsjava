package org.xbill.DNS;

import lombok.Getter;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

@Getter
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
    this.localAddress = localAddress;  //Objects.requireNonNull(localAddress, "localAddress must not be null");
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

    // SOCKS5 method selection transaction
    CompletableFuture<byte[]> methodSelectionF = new CompletableFuture<>();
    NioSocksHandler.MethodSelectionRequest methodSelectionRequest = getMethodSelectionRequest();
    NioTcpHandler.Transaction methodSelectionTransaction = new NioTcpHandler.Transaction(
      query, methodSelectionRequest.toBytes(), endTime, channel.getChannel(), methodSelectionF);
    channel.queueTransaction(methodSelectionTransaction);
    methodSelectionF.thenComposeAsync(
      methodSelectionBytes -> {
        if (methodSelectionBytes.length != 2) {
          authHandshakeF.completeExceptionally(new UnsupportedOperationException("Invalid SOCKS5 method selection response"));
        }
        NioSocksHandler.MethodSelectionResponse methodSelectionResponse = new NioSocksHandler.MethodSelectionResponse(methodSelectionBytes);
        if (methodSelectionResponse.getMethod() == NioSocksHandler.SOCKS5_AUTH_NO_ACCEPTABLE_METHODS) {
          authHandshakeF.completeExceptionally(new UnsupportedOperationException("Unsupported SOCKS5 method: " + methodSelectionResponse.getMethod()));
        } else {
          if (methodSelectionResponse.getMethod() == NioSocksHandler.SOCKS5_AUTH_NONE) {
            authHandshakeF.complete(null);
          }
//          else if (methodSelectionResponse.getMethod() == NioSocksHandler.SOCKS5_AUTH_USER_PASS) {
//            // SOCKS5 authentication transaction (if required)
//            CompletableFuture<byte[]> userPassAuthF = new CompletableFuture<>();
//            UserPassAuthRequest userPassAuthRequest = getUserPassAuthRequest();
//            NioTcpHandler.Transaction userPwdAuthTransaction = NioTcpHandler.Transaction(query, userPassAuthRequest.toBytes(), endTime, channel.getChannel(), userPassF);
//            channel.queueTransaction(userPwdAuthTransaction);
//            userPassAuthF.thenComposeAsync(
//              authIn -> {
//                CompletableFuture<byte[]> authF = new CompletableFuture<>();
//                UserPwdAuthResponse userPwdAuthResponse = UserPwdAuthResponse.fromBytes(authIn);
//                if (userPwdAuthResponse.getStatus() != NioSocksHandler.SOCKS5_REP_SUCCEEDED) {
//                  authHandshakeF.completeExceptionally(
//                    new UnsupportedOperationException("SOCKS5 user/pwd authentication failed with status: " + userPwdAuthResponse.getStatus()));
//                } else {
//                  authF.complete(authIn);
//                }
//                return authF;
//              }
//            );
//          }
        }
        return null;
      }
    );

    return authHandshakeF;
  }

  public CompletableFuture<byte[]> doConnectHandshake(NioTcpHandler.ChannelState channel, Message query, long endTime) {
    CompletableFuture<byte[]> cmdHandshakeF = new CompletableFuture<>();

    // SOCKS5 cmd transaction
    CompletableFuture<byte[]> commandF = new CompletableFuture<>();
    CmdRequest cmdRequest = new CmdRequest(SOCKS5_CMD_CONNECT, remoteAddress);
    NioTcpHandler.Transaction commandTransaction = new NioTcpHandler.Transaction(
      query, cmdRequest.toBytes(), endTime, channel.getChannel(), commandF);
    channel.queueTransaction(commandTransaction);
    commandF.thenComposeAsync(
      in -> {
        CmdResponse cmdResponse = new CmdResponse(in);
        if (cmdResponse.getReply() != NioSocksHandler.SOCKS5_REP_SUCCEEDED) {
          cmdHandshakeF.completeExceptionally(
            new UnsupportedOperationException("SOCKS5 command failed with status: " + cmdResponse.getReply()));
        } else {
          cmdHandshakeF.complete(in);
        }
        return null;
      }
    );

    return cmdHandshakeF;
  }
  public CompletableFuture<byte[]> doUdpAssociateHandshake(NioTcpHandler.ChannelState channel, Message query, long endTime) {
    CompletableFuture<byte[]> cmdHandshakeF = new CompletableFuture<>();

    // SOCKS5 cmd transaction
    CompletableFuture<byte[]> commandF = new CompletableFuture<>();
    CmdRequest cmdRequest = new CmdRequest(SOCKS5_CMD_UDP_ASSOCIATE, new InetSocketAddress("0.0.0.0", 0));
    NioTcpHandler.Transaction commandTransaction = new NioTcpHandler.Transaction(
      query, cmdRequest.toBytes(), endTime, channel.getChannel(), commandF);
    channel.queueTransaction(commandTransaction);
    commandF.thenComposeAsync(
      in -> {
        CmdResponse cmdResponse = new CmdResponse(in);
        if (cmdResponse.getReply() != NioSocksHandler.SOCKS5_REP_SUCCEEDED) {
          cmdHandshakeF.completeExceptionally(
            new UnsupportedOperationException("SOCKS5 command failed with status: " + cmdResponse.getReply()));
        } else {
          cmdHandshakeF.complete(in);
        }
        return null;
      }
    );

    return cmdHandshakeF;
  }

  public synchronized CompletableFuture<byte[]> doSocks5Handshake(NioTcpHandler.ChannelState channel, byte socks5Cmd, Message query, long endTime) {
    CompletableFuture<byte[]> socks5HandshakeF = new CompletableFuture<>();
    channel.setSocks5(true);

    CompletableFuture<Void> authHandshakeF = doAuthHandshake(channel, query, endTime);
    authHandshakeF.thenRunAsync(
      () -> {
        CompletableFuture<byte[]> cmdHandshakeF;
        if (socks5Cmd == SOCKS5_CMD_CONNECT) {
          cmdHandshakeF = doConnectHandshake(channel, query, endTime);
        } else if (socks5Cmd == SOCKS5_CMD_UDP_ASSOCIATE) {
          cmdHandshakeF = doUdpAssociateHandshake(channel, query, endTime);
        } else {
          cmdHandshakeF = CompletableFuture.failedFuture(new UnsupportedOperationException("Unsupported SOCKS5 command: " + socks5Cmd));
        }
        cmdHandshakeF.thenComposeAsync(
          in -> {
            socks5HandshakeF.complete(in);
            return null;
          }
        ).exceptionally(
          e -> {
            socks5HandshakeF.completeExceptionally(e);
            return null;
          }
        );
      }
    ).exceptionally(
      e -> {
        socks5HandshakeF.completeExceptionally(e);
        return null;
      }
    );

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
    buffer.put(addressType); // ATYP (IPv4)
    if (addressType == SOCKS5_ATYP_DOMAINNAME) {
      buffer.put((byte) addressBytes.length);
    }
    buffer.put(addressBytes); // DST.ADDR
    buffer.putShort((short) remoteAddress.getPort()); // DST.PORT
    buffer.put(data); // DATA

    return buffer.array();
  }

  public byte[] removeUdpHeader(byte[] in) {
    byte[] out = new byte[in.length - 10];
    System.arraycopy(in, 10, out, 0, in.length - 10);
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
      version = buffer.get();;
      method = buffer.get();;
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
      version = SOCKS5_VERSION;
      this.command = command;
      reserved = SOCKS5_RESERVED;
      if (address.getAddress() instanceof Inet4Address) {
        addressType = SOCKS5_ATYP_IPV4;
        addressBytes = address.getAddress().getAddress();
        bufferSize = 10;
      } else if (address.getAddress() instanceof Inet6Address) {
        addressType = SOCKS5_ATYP_IPV6;
        addressBytes = address.getAddress().getAddress();
        bufferSize = 22;
      } else {
        addressType = SOCKS5_ATYP_DOMAINNAME;
        addressBytes = address.getHostName().getBytes(StandardCharsets.UTF_8);
        bufferSize = 7 + addressBytes.length;
      }
      port = (short) address.getPort();
    }

    public byte[] toBytes() {
      ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
      buffer.put(this.version);
      buffer.put(this.command);
      buffer.put(this.reserved);
      buffer.put(this.addressType);
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
      version = buffer.get();
      reply = buffer.get();
      reserved = buffer.get();
      addressType = buffer.get();
      address = new byte[addressType == SOCKS5_ATYP_IPV4 ? 4 : 16];
      buffer.get(address);
      // Short.toUnsignedInt makes a difference for port numbers higher than 32767
      port = Short.toUnsignedInt(buffer.getShort());
    }
  }
}
