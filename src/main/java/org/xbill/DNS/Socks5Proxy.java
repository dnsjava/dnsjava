package org.xbill.DNS;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

@Slf4j
@Getter
@Setter
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

  public enum State {
    INIT,
    UDP_ASSOCIATE,
    CONNECTED,
    FAILED
  }

  public enum Command {
    CONNECT,
    UDP_ASSOCIATE
  }

  private final Socks5ProxyConfig config;
  private final InetSocketAddress local;
  private final InetSocketAddress remote;
  private SelectionKey tcpSelectionKey;
  private DatagramChannel udpChannel;
  private final Command command;
  private State state = State.INIT;

  public Socks5Proxy(
    SelectionKey tcpSelectionKey,
    Socks5ProxyConfig config,
    InetSocketAddress local,
    InetSocketAddress remote,
    Command command) {
    this.tcpSelectionKey = tcpSelectionKey;
    this.config = config;
    this.local = local;
    this.remote = remote;
    this.command = command;
  }

  public void handleSOCKS5(CompletableFuture<Void> future) {
    tcpSelectionKey.attach(new ConnectHandler(future));
    tcpSelectionKey.interestOps(SelectionKey.OP_CONNECT);
    tcpSelectionKey.selector().wakeup();
  }

  public ByteBuffer addSocks5UdpAssociateHeader(byte[] data) {
    ByteBuffer buffer;
    byte addressType;
    byte[] addressBytes;
    if (remote.getAddress() instanceof Inet4Address) {
      addressType = SOCKS5_ATYP_IPV4;
      addressBytes = remote.getAddress().getAddress();
      buffer = ByteBuffer.allocate(4 + addressBytes.length + 2 + data.length);
    } else if (remote.getAddress() instanceof Inet6Address) {
      addressType = SOCKS5_ATYP_IPV6;
      addressBytes = remote.getAddress().getAddress();
      buffer = ByteBuffer.allocate(4 + addressBytes.length + 2 + data.length);
    } else {
      addressType = SOCKS5_ATYP_DOMAINNAME;
      addressBytes = remote.getHostName().getBytes(StandardCharsets.UTF_8);
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
    buffer.putShort((short) remote.getPort()); // DST.PORT
    buffer.put(data); // DATA

    return buffer;
  }

  private class ConnectHandler implements Runnable {
    private final CompletableFuture<Void> future;

    ConnectHandler(CompletableFuture<Void> future) {
      this.future = future;
    }

    @Override
    public void run() {
      try {
        SocketChannel channel = (SocketChannel) tcpSelectionKey.channel();
        if (channel.finishConnect()) {
          // Connection finished successfully
          tcpSelectionKey.attach(new Socks5MethodSelectionHandler(future));
          tcpSelectionKey.interestOps(SelectionKey.OP_WRITE);
        } else {
          // Connection not finished, re-register for OP_CONNECT
          tcpSelectionKey.interestOps(SelectionKey.OP_CONNECT);
        }
        tcpSelectionKey.selector().wakeup();
      } catch (IOException e) {
        future.completeExceptionally(e);
      }
    }
  }

  private class Socks5MethodSelectionHandler implements Runnable {
    private final CompletableFuture<Void> future;

    Socks5MethodSelectionHandler(CompletableFuture<Void> future) {
      this.future = future;
    }

    @Override
    public void run() {
      try {
        SocketChannel channel = (SocketChannel) tcpSelectionKey.channel();
        ByteBuffer buffer = ByteBuffer.allocate(3);
        buffer.put(SOCKS5_VERSION);
        buffer.put((byte) 1);
        buffer.put((config.getAuthMethod() == Socks5ProxyConfig.AuthMethod.USER_PASS) ? SOCKS5_AUTH_USER_PASS : SOCKS5_AUTH_NONE);
        buffer.flip();
        channel.write(buffer);

        tcpSelectionKey.attach(new Socks5MethodSelectionReadHandler(future));
        tcpSelectionKey.interestOps(SelectionKey.OP_READ);
        tcpSelectionKey.selector().wakeup();
      } catch (IOException e) {
        future.completeExceptionally(e);
      }
    }
  }

  private class Socks5MethodSelectionReadHandler implements Runnable {
    private final CompletableFuture<Void> future;

    Socks5MethodSelectionReadHandler(CompletableFuture<Void> future) {
      this.future = future;
    }

    @Override
    public void run() {
      try {
        SocketChannel channel = (SocketChannel) tcpSelectionKey.channel();
        ByteBuffer buffer = ByteBuffer.allocate(2);
        channel.read(buffer);
        buffer.flip();

        if (buffer.get() != SOCKS5_VERSION) {
          throw new IllegalStateException("Invalid SOCKS5 version");
        }

        byte method = buffer.get();
        if (method == SOCKS5_AUTH_NO_ACCEPTABLE_METHODS) {
          throw new IllegalStateException("No acceptable authentication methods");
        }

        if (method == SOCKS5_AUTH_USER_PASS) {
          tcpSelectionKey.attach(new Socks5UserPassAuthHandler(future));
        } else {
          if (command == Command.CONNECT) {
            tcpSelectionKey.attach(new Socks5ConnectExchangeHandler(future));
          } else if (command == Command.UDP_ASSOCIATE) {
            tcpSelectionKey.attach(new Socks5UdpAssociateExchangeHandler(future));
          } else {
            throw new IllegalStateException("Unsupported command: " + command);
          }
        }

        tcpSelectionKey.interestOps(SelectionKey.OP_WRITE);
        tcpSelectionKey.selector().wakeup();
      } catch (IOException | IllegalStateException e) {
        future.completeExceptionally(e);
      }
    }
  }

  private class Socks5UserPassAuthHandler implements Runnable {
    private final CompletableFuture<Void> future;

    Socks5UserPassAuthHandler(CompletableFuture<Void> future) {
      this.future = future;
    }

    @Override
    public void run() {
      try {
        SocketChannel channel = (SocketChannel) tcpSelectionKey.channel();
        ByteBuffer buffer = ByteBuffer.allocate(2 + config.getSocks5User().length() + 2 + config.getSocks5Password().length());
        buffer.put(SOCKS5_USER_PWD_AUTH_VERSION);
        buffer.put((byte) config.getSocks5User().length());
        buffer.put(config.getSocks5User().getBytes());
        buffer.put((byte) config.getSocks5Password().length());
        buffer.put(config.getSocks5Password().getBytes());
        buffer.flip();
        channel.write(buffer);

        tcpSelectionKey.attach(new Socks5UserPassAuthReadHandler(future));
        tcpSelectionKey.interestOps(SelectionKey.OP_READ);
        tcpSelectionKey.selector().wakeup();
      } catch (IOException e) {
        future.completeExceptionally(e);
      }
    }
  }

  private class Socks5UserPassAuthReadHandler implements Runnable {
    private final CompletableFuture<Void> future;

    Socks5UserPassAuthReadHandler(CompletableFuture<Void> future) {
      this.future = future;
    }

    @Override
    public void run() {
      try {
        SocketChannel channel = (SocketChannel) tcpSelectionKey.channel();
        ByteBuffer buffer = ByteBuffer.allocate(2);
        channel.read(buffer);
        buffer.flip();

        if (buffer.get() != SOCKS5_USER_PWD_AUTH_VERSION) {
          throw new IllegalStateException("Invalid SOCKS5 user/password auth version");
        }

        byte status = buffer.get();
        if (status != 0x00) {
          throw new IllegalStateException("User/password authentication failed");
        }

        if (command == Command.CONNECT) {
          tcpSelectionKey.attach(new Socks5ConnectExchangeHandler(future));
        } else if (command == Command.UDP_ASSOCIATE) {
          tcpSelectionKey.attach(new Socks5UdpAssociateExchangeHandler(future));
        } else {
          throw new IllegalStateException("Unsupported command: " + command);
        }
        tcpSelectionKey.interestOps(SelectionKey.OP_WRITE);
        tcpSelectionKey.selector().wakeup();
      } catch (IOException | IllegalStateException e) {
        future.completeExceptionally(e);
      }
    }
  }

  private class Socks5ConnectExchangeHandler implements Runnable {
    private final CompletableFuture<Void> future;

    Socks5ConnectExchangeHandler(CompletableFuture<Void> future) {
      this.future = future;
    }

    @Override
    public void run() {
      try {
        SocketChannel channel = (SocketChannel) tcpSelectionKey.channel();
        ByteBuffer buffer;
        byte addressType;
        byte[] addressBytes;

        if (remote.getAddress() instanceof Inet4Address) {
          addressType = SOCKS5_ATYP_IPV4;
          addressBytes = remote.getAddress().getAddress();
          buffer = ByteBuffer.allocate(10);
        } else if (remote.getAddress() instanceof Inet6Address) {
          addressType = SOCKS5_ATYP_IPV6;
          addressBytes = remote.getAddress().getAddress();
          buffer = ByteBuffer.allocate(22);
        } else {
          addressType = SOCKS5_ATYP_DOMAINNAME;
          addressBytes = remote.getHostName().getBytes(StandardCharsets.UTF_8);
          buffer = ByteBuffer.allocate(7 + addressBytes.length);
        }

        buffer.put(SOCKS5_VERSION);
        buffer.put(SOCKS5_CMD_CONNECT);
        buffer.put(SOCKS5_RESERVED);
        buffer.put(addressType);
        if (addressType == SOCKS5_ATYP_DOMAINNAME) {
          buffer.put((byte) addressBytes.length);
        }
        buffer.put(addressBytes);
        buffer.putShort((short) remote.getPort());
        buffer.flip();
        channel.write(buffer);

        tcpSelectionKey.attach(new Socks5HeaderExchangeReadHandler(future));
        tcpSelectionKey.interestOps(SelectionKey.OP_READ);
        tcpSelectionKey.selector().wakeup();
      } catch (IOException e) {
        future.completeExceptionally(e);
      }
    }
  }

  private class Socks5UdpAssociateExchangeHandler implements Runnable {
    private final CompletableFuture<Void> future;

    Socks5UdpAssociateExchangeHandler(CompletableFuture<Void> future) {
      this.future = future;
    }

    @Override
    public void run() {
      try {
        SocketChannel channel = (SocketChannel) tcpSelectionKey.channel();
        ByteBuffer buffer = ByteBuffer.allocate(10);
        buffer.put(SOCKS5_VERSION);
        buffer.put(SOCKS5_CMD_UDP_ASSOCIATE);
        buffer.put(SOCKS5_RESERVED);
        // For UDP associate this is not the remote address,
        // but the address where the proxy will send UDP packets after receiving them from the remote address
        // there is a header for the remote address in the UDP packet
        buffer.put(SOCKS5_ATYP_IPV4);
        buffer.putInt(0); // 0.0.0.0  (this way it works in nat-ed networks)
        buffer.putShort((short) 0); // Port 0
        buffer.flip();
        channel.write(buffer);

        tcpSelectionKey.attach(new Socks5HeaderExchangeReadHandler(future));
        tcpSelectionKey.interestOps(SelectionKey.OP_READ);
        tcpSelectionKey.selector().wakeup();
      } catch (IOException e) {
        future.completeExceptionally(e);
      }
    }
  }

  private class Socks5HeaderExchangeReadHandler implements Runnable {
    private final CompletableFuture<Void> future;

    Socks5HeaderExchangeReadHandler(CompletableFuture<Void> future) {
      this.future = future;
    }

    @Override
    public void run() {
      try {
        SocketChannel channel = (SocketChannel) tcpSelectionKey.channel();
        // Allocate 262 bytes to handle the maximum possible size of the SOCKS5 reply
        ByteBuffer buffer = ByteBuffer.allocate(262);
        channel.read(buffer);
        buffer.flip();

        if (buffer.get() != SOCKS5_VERSION) {
          throw new IllegalStateException("Invalid SOCKS5 version");
        }

        byte reply = buffer.get();
        if (reply != SOCKS5_REP_SUCCEEDED) {
          throw new IllegalStateException("Connection to remote server failed: " + reply);
        }

        if (command == Command.CONNECT) {
          state = State.CONNECTED;
          // ignore rest of the reply
        } else {
          state = State.UDP_ASSOCIATE;
          // get the bound port for UDP associate
          /// skip reserved byte
          buffer.get();
          /// read the bound address and port
          byte addressType = buffer.get();
          byte[] boundAddress;
          if (addressType == SOCKS5_ATYP_IPV4) {
            boundAddress = new byte[4];
          } else if (addressType == SOCKS5_ATYP_IPV6) {
            boundAddress = new byte[16];
          } else if (addressType == SOCKS5_ATYP_DOMAINNAME) {
            int domainLength = buffer.get();
            boundAddress = new byte[domainLength];
          } else {
            throw new IllegalStateException("Unsupported address type: " + addressType);
          }
          buffer.get(boundAddress);
          // Short.toUnsignedInt makes a difference for port numbers higher than 32767
          int udpAssociatePort = Short.toUnsignedInt(buffer.getShort());
          udpChannel = DatagramChannel.open();
          udpChannel.configureBlocking(false);
          udpChannel.bind(new InetSocketAddress(local.getAddress(), 0));
          udpChannel.connect(new InetSocketAddress(config.getProxyAddress().getAddress(), udpAssociatePort));
        }

        future.complete(null);
      } catch (IOException e) {
        future.completeExceptionally(e);
      }
    }
  }
}
