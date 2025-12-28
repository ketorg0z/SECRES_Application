package com.example.analyseurtrafic;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;


public class VPN extends VpnService {

    public static final String ACTION_PACKET_RECEIVED = "com.example.analyseurtrafic.PACKET_RECEIVED";
    public static final String EXTRA_PACKET_INFO = "packet_info";

    private static final String TAG = "MyVPN";
    private ParcelFileDescriptor vpnInterface = null;
    private Thread vpnThread;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        vpnThread = new Thread(() -> {
            try {
                runVpn();
            } catch (Exception e) {
                Log.e(TAG, "Error running VPN", e);
                if (!(e instanceof InterruptedException)) {
                    e.printStackTrace();
                }
            } finally {
                stopVpn();
            }
        });
        vpnThread.start();
        return START_STICKY;
    }

    private void runVpn() throws Exception {
        try {
            // 1. Configure the VPN interface
            Builder builder = new Builder();
            builder.setSession("AnalyseurTrafic");
            builder.addAddress("10.0.0.2", 24); // Internal IP address for the VPN interface
            builder.addRoute("0.0.0.0", 0);   // Route all traffic through the VPN

            // 2. Establish the VPN interface
            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "VPN interface not established");
                return;
            }

            // 3. Get the input and output streams
            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());

            // 4. Start reading and writing packets (the core logic of your packet analyzer)
            // For now, this loop will just read packets and log their size.
            byte[] packet = new byte[32767];

            byte[] buffer = new byte[32767];

            while (true) {
                int length = in.read(buffer);
                if (length > 0) {

                    String info = defineIPVersion(buffer, length);
                    sendToUI(info);

                    if ((buffer[0] >> 4) == 4 && buffer[9] == 17) {
                        handleUdpPackets(buffer, length, out);
                    }

                    // out.write(buffer, 0, length);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "VPN error", e);
        }
    }

    private String defineIPVersion(byte[] data, int length) {
        try {
            Packet packet;

            // Detect IPv4 or IPv6
            if ((data[0] >> 4) == 4) {
                packet = IpV4Packet.newPacket(data, 0, length);
                return parseIPv4((IpV4Packet) packet);
            } else if ((data[0] >> 4) == 6) {
                packet = IpV6Packet.newPacket(data, 0, length);
                return parseIPv6((IpV6Packet) packet);
            } else {
                return "Unknown L3 Packet";
            }

        } catch (Exception e) {
            return "Malformed packet (" + length + " bytes)";
        }
    }

    private String parseIPv4(IpV4Packet ip) {

        int protocol = ip.getHeader().getProtocol().value();
        String src = ip.getHeader().getSrcAddr().getHostAddress();
        String dst = ip.getHeader().getDstAddr().getHostAddress();

        if (protocol == 6) { // TCP
            TcpPacket tcp = ip.get(TcpPacket.class);
            int sport = tcp.getHeader().getSrcPort().valueAsInt();
            int dport = tcp.getHeader().getDstPort().valueAsInt();

            if (sport == 389 || dport == 389) {
                String ldapData = decodeTCP(tcp);
                return "IPv4 | TCP | LDAP | " + src + " → " + dst + "Data : " + ldapData;
            }

            return "IPv4 | TCP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);
        } else if (protocol == 17) { // UDP
            UdpPacket udp = ip.get(UdpPacket.class);
            int sport = udp.getHeader().getSrcPort().valueAsInt();
            int dport = udp.getHeader().getDstPort().valueAsInt();

            if (sport == 123 || dport == 123) {
                String ntpData = decodeNTP(udp);
                return "IPv4 | UDP | NTP | " + src + " → " + dst + "Data : " + ntpData;
            }

            return "IPv4 | UDP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (protocol == 1) { // ICMPv4
            return "IPv4 | ICMP | " + src + " → " + dst;
        }

        return "IPv4 | Protocol " + protocol + " | " + src + " → " + dst;
    }

    private String parseIPv6(IpV6Packet ip) {

        int protocol = ip.getHeader().getNextHeader().value();
        String src = ip.getHeader().getSrcAddr().getHostAddress();
        String dst = ip.getHeader().getDstAddr().getHostAddress();

        if (protocol == 6) { // TCP
            TcpPacket tcp = ip.get(TcpPacket.class);
            int sport = tcp.getHeader().getSrcPort().valueAsInt();
            int dport = tcp.getHeader().getDstPort().valueAsInt();

            if (sport == 389 || dport == 389) {
                String ldapData = decodeTCP(tcp);
                return "IPv4 | TCP | LDAP | " + src + " → " + dst + "Data : " + ldapData;
            }

            return "IPv6 | TCP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (protocol == 17) { // UDP
            UdpPacket udp = ip.get(UdpPacket.class);
            int sport = udp.getHeader().getSrcPort().valueAsInt();
            int dport = udp.getHeader().getDstPort().valueAsInt();

            if (sport == 123 || dport == 123) {
                String ntpData = decodeNTP(udp);
                return "IPv4 | UDP | NTP | " + src + " → " + dst + "Data : " + ntpData;
            }

            return "IPv6 | UDP | " + src + ":" + sport + " → " + dst + ":" + dport +
                    identifyAppProtocol(dport);

        } else if (protocol == 58) { // ICMPv6
            return "IPv6 | ICMPv6 | " + src + " → " + dst;
        }

        return "IPv6 | Protocol " + protocol + " | " + src + " → " + dst;
    }

    private String identifyAppProtocol(int port) {
        if (port == 80) return " (HTTP)";
        if (port == 443) return " (HTTPS)";
        if (port == 53) return " (DNS)";
        if (port == 123) return " (NTP)";
        if (port == 389) return " (LDAP)";
        return "";
    }

    private void handleUdpPackets(byte[] packetData, int length, FileOutputStream out) {
        java.net.DatagramSocket tunnel = null;

        try {
            IpV4Packet ipPacket = IpV4Packet.newPacket(packetData, 0, length);
            UdpPacket udpPacket = ipPacket.get(UdpPacket.class);

            if (udpPacket == null) return;

            String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
            int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();

            // 1. Create an UNBOUND socket (pass null)
            tunnel = new java.net.DatagramSocket(null);

            // 2. CRITICAL: Protect the socket BEFORE binding or connecting
            // This tells the OS: "Let this socket bypass the VPN interface"
            if (!this.protect(tunnel)) {
                Log.e(TAG, "Failed to protect socket - Loopback prevented");
                tunnel.close();
                return;
            }

            // 3. Now bind it to any available local port
            tunnel.bind(new java.net.InetSocketAddress(0));

            // 4. Set a short timeout (e.g., 2 seconds) so we don't freeze the app
            tunnel.setSoTimeout(5000);

            // 4. Send the data
            byte[] payload = udpPacket.getPayload().getRawData();
            java.net.DatagramPacket outPacket = new java.net.DatagramPacket(payload, payload.length,
                    java.net.InetAddress.getByName(dstIp), dstPort);

            Log.d(TAG, "Attempting to forward UDP to: " + dstIp + ":" + dstPort);
            tunnel.send(outPacket);

            // 5. Read response
            byte[] receiveData = new byte[32767];
            java.net.DatagramPacket inPacket = new java.net.DatagramPacket(receiveData, receiveData.length);

            // This will throw SocketTimeoutException if no reply comes in 2s
            tunnel.receive(inPacket);

            // 6. We got a reply! Build the response packet.
            int bytesRead = inPacket.getLength();

            // Extract the raw data returned by the server
            byte[] responseData = new byte[bytesRead];
            System.arraycopy(inPacket.getData(), 0, responseData, 0, bytesRead);

            UnknownPacket payloadObj = new UnknownPacket.Builder()
                    .rawData(responseData)
                    .build();

            // Build UDP Header (SWAPPING PORTS)
            UdpPacket responseUdp = new UdpPacket.Builder()
                    .srcPort(udpPacket.getHeader().getDstPort()) // Server Port -> Source
                    .dstPort(udpPacket.getHeader().getSrcPort()) // Phone Port -> Dest
                    .srcAddr(ipPacket.getHeader().getDstAddr())
                    .dstAddr(ipPacket.getHeader().getSrcAddr())
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true)
                    .payloadBuilder(payloadObj.getBuilder())
                    .build();

            // Build IP Header (SWAPPING ADDRESSES)
            IpV4Packet responseIp = new IpV4Packet.Builder()
                    .version(IpVersion.IPV4)
                    .tos(ipPacket.getHeader().getTos())
                    .protocol(IpNumber.UDP)
                    .srcAddr(ipPacket.getHeader().getDstAddr()) // Server IP -> Source
                    .dstAddr(ipPacket.getHeader().getSrcAddr()) // Phone IP -> Dest
                    .payloadBuilder(responseUdp.getBuilder())
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true)
                    .build();

            byte[] responseBytes = responseIp.getRawData();
            String responseInfo = defineIPVersion(responseBytes, responseBytes.length);
            sendToUI("<< RESPONSE: " + responseInfo);

            // 7. Write back to VPN
            out.write(responseBytes);


        } catch (Exception e) {
            Log.e(TAG, "UDP handling error" + e.getMessage());
        } finally {
            if (tunnel != null) {
                tunnel.close();
            }
        }
    }

    private String decodeTCP(TcpPacket tcp) {
        if (tcp.getPayload() == null) return "Empty Payload";

        byte[] data = tcp.getPayload().getRawData();
        if (data.length == 0) return "No Data";
        StringBuilder content = new StringBuilder();
        StringBuilder currentSegment = new StringBuilder();

        for (byte b : data) {
            // Check if char is printable (ASCII 32-126)
            if (b >= 32 && b <= 126) {
                currentSegment.append((char) b);
            } else {
                // End of a printable sequence
                if (currentSegment.length() > 3) {
                    if (content.length() > 0) content.append(", ");
                    content.append(currentSegment);
                }
                currentSegment.setLength(0); // Reset
            }
        }

        if (currentSegment.length() > 3) {
            if (content.length() > 0) content.append(", ");
            content.append(currentSegment);
        }

        if (content.length() == 0) return "Binary/Encrypted Data";

        // Limit length
        String result = content.toString();
        if (result.length() > 100) return result.substring(0, 100) + "...";
        return result;
    }

    private String decodeNTP(UdpPacket udp) {
        if (udp.getPayload() == null) return "Empty Payload";

        byte[] data = udp.getPayload().getRawData();
        if (data.length < 48) return "Too Short";

        // NTP Header Format (First Byte):
        // LI (2 bits) | VN (3 bits) | Mode (3 bits)

        int firstByte = data[0] & 0xFF; // Convert signed byte to unsigned int

        int leapIndicator = (firstByte >> 6) & 0x03;
        int version = (firstByte >> 3) & 0x07;
        int mode = firstByte & 0x07;

        String modeStr;
        switch (mode) {
            case 1: modeStr = "Symmetric Active"; break;
            case 2: modeStr = "Symmetric Passive"; break;
            case 3: modeStr = "Client"; break;
            case 4: modeStr = "Server"; break;
            case 5: modeStr = "Broadcast"; break;
            default: modeStr = "Mode " + mode;
        }

        // Transmit Timestamp decoding

        long seconds = 0;
        for (int i = 40; i <= 43; i++) {
            seconds = (seconds << 8) | (data[i] & 0xFF);
        }

        String timeString;
        if (seconds > 0) {
            //Difference between 1900 (NTP) and 1970 (Java)

            long seconds1970 = seconds - 2208988800L;
            long javaTimeMillis = seconds1970 * 1000;

            java.util.Date date = new java.util.Date(javaTimeMillis);
            java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("HH:mm:ss");
            timeString = sdf.format(date);
        } else {
            timeString = "Unknown";
        }

        return "Ver: " + version + ",  LI : " + leapIndicator + ",  Type: " + modeStr + ", Time: " + timeString;
    }

    private String decodeLDAP(byte[] data) {
        return "LDAP Data";
    }



    private void sendToUI(String text) {
        Intent intent = new Intent(ACTION_PACKET_RECEIVED);
        intent.putExtra(EXTRA_PACKET_INFO, text);
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
    }
    private void stopVpn() {
        if (vpnThread != null) {
            vpnThread.interrupt();
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException e) {
                Log.e(TAG, "Error closing VPN interface", e);
            }
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        stopVpn();
    }
}

