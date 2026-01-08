package com.example.analyseurtrafic;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
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
    private ExecutorService udpExecutor;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        udpExecutor = Executors.newCachedThreadPool();

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
            // Configuring the VPN interface
            Builder builder = new Builder();
            builder.setSession("AnalyseurTrafic");
            builder.addAddress("10.0.0.2", 24); // Internal IP address for the VPN interface
            builder.addRoute("0.0.0.0", 0);   // Route all traffic through the VPN
            builder.addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128);
            builder.addRoute("0:0:0:0:0:0:0:0", 0);

            // Establish the VPN interface
            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "VPN interface not established");
                return;
            }

            // Get the input and output streams
            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());

            // Start reading packets
            byte[] packet = new byte[32767];

            byte[] buffer = new byte[32767];

            while (true) {
                int length = in.read(buffer);
                if (length > 0) {

                    String info = defineIPVersion(buffer, length);
                    sendToUI(info);

                    if ((buffer[0] >> 4) == 4 && buffer[9] == 17) {
                        byte[] packetCopy = new byte[length];
                        System.arraycopy(buffer, 0, packetCopy, 0, length);

                        udpExecutor.submit(() -> {
                           handleUdpPackets(packetCopy, length, out);
                        });
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

            if (sport == 80 || dport == 80) {
                return "IPv4 | TCP | HTTP | " + src + " → " + dst + " | " + decodeHTTP(tcp);
            }

            if (dport == 22 || sport == 22) {
                String sshInfo = analyzeSSH(tcp);
                if (sshInfo != null) {
                    return "IPv4 | TCP | SSH | " + src + " → " + dst + " | " + sshInfo;
                } else {
                    return "IPv4 | TCP | SSH | " + src + " → " + dst;
                }
            }

            if (dport == 23 || sport == 23) {
                String telnetData = decodeTelnet(tcp);
                return "IPv4 | TCP | TELNET | " + src + " → " + dst + " | Data: " + telnetData;
            }

            if (sport == 389 || dport == 389) {
                String ldapData = decodeTCP(tcp);
                return "IPv4 | TCP | LDAP | " + src + " → " + dst + "Data : " + ldapData;
            }

            return "IPv4 | TCP | " + identifyAppProtocol(dport) + " | " +  src + ":" + sport + " → " + dst + ":" + dport;
        } else if (protocol == 17) { // UDP
            UdpPacket udp = ip.get(UdpPacket.class);
            int sport = udp.getHeader().getSrcPort().valueAsInt();
            int dport = udp.getHeader().getDstPort().valueAsInt();

            if (sport == 53 || dport == 53) {
                return "IPv4 | UDP | DNS | " + src + " → " + dst + " | " + decodeDNS(udp);
            }
            if (sport == 123 || dport == 123) {
                String ntpData = decodeNTP(udp);
                return "IPv4 | UDP | NTP | " + src + " → " + dst + "Data : " + ntpData;
            }

            return "IPv4 | UDP | " + identifyAppProtocol(dport) + " | " + src + ":" + sport + " → " + dst + ":" + dport;

        } else if (protocol == 1) {
            return analyzeICMPv4(ip);
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

            if (sport == 80 || dport == 80) {
                return "IPv6 | TCP | HTTP | " + src + " → " + dst + " | " + decodeHTTP(tcp);
            }

            if (sport == 389 || dport == 389) {
                String ldapData = decodeTCP(tcp);
                return "IPv6 | TCP | LDAP | " + src + " → " + dst + "Data : " + ldapData;
            }

            return "IPv6 | TCP | " + identifyAppProtocol(dport) + " | " +  src + ":" + sport + " → " + dst + ":" + dport;

        } else if (protocol == 17) { // UDP
            UdpPacket udp = ip.get(UdpPacket.class);
            int sport = udp.getHeader().getSrcPort().valueAsInt();
            int dport = udp.getHeader().getDstPort().valueAsInt();

            if (sport == 53 || dport == 53) {
                return "IPv6 | UDP | DNS | " + src + " → " + dst + " | " + decodeDNS(udp);
            }

            if (sport == 123 || dport == 123) {
                String ntpData = decodeNTP(udp);
                return "IPv6 | UDP | NTP | " + src + " → " + dst + "Data : " + ntpData;
            }

            return "IPv6 | UDP | " + identifyAppProtocol(dport) + " | " + src + ":" + sport + " → " + dst + ":" + dport;

        } else if (protocol == 58) { // ICMPv6
            return analyzeICMPv6(ip);
        }

        return "IPv6 | Protocol " + protocol + " | " + src + " → " + dst;
    }

    private String identifyAppProtocol(int port) {
        if (port == 22) return "SSH";
        if (port == 23) return "TELNET";
        if (port == 161 || port == 162) return "SNMP";
        if (port == 3389) return "RDP";
        if (port == 389) return "LDAP";
        if (port == 123) return "NTP";
        if (port == 80) return "HTTP";
        if (port == 443) return "HTTPS";
        if (port == 53) return "DNS";
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

            // Unbound socket create (pass null)
            tunnel = new java.net.DatagramSocket(null);

            // Protecting the socket before binding or connecting
            if (!this.protect(tunnel)) {
                Log.e(TAG, "Failed to protect socket - Loopback prevented");
                tunnel.close();
                return;
            }

            tunnel.bind(new java.net.InetSocketAddress(0));

            // 5 seconds timeout
            tunnel.setSoTimeout(5000);

            // Sending the data
            byte[] payload = udpPacket.getPayload().getRawData();
            java.net.DatagramPacket outPacket = new java.net.DatagramPacket(payload, payload.length,
                    java.net.InetAddress.getByName(dstIp), dstPort);

            Log.d(TAG, "Attempting to forward UDP to: " + dstIp + ":" + dstPort);
            tunnel.send(outPacket);

            byte[] receiveData = new byte[32767];
            java.net.DatagramPacket inPacket = new java.net.DatagramPacket(receiveData, receiveData.length);

            // Throwing SocketTimeoutException if no reply comes in 2s
            tunnel.receive(inPacket);

            // Building a response packet
            int bytesRead = inPacket.getLength();

            // Extract the raw data returned by the server
            byte[] responseData = new byte[bytesRead];
            System.arraycopy(inPacket.getData(), 0, responseData, 0, bytesRead);

            UnknownPacket payloadObj = new UnknownPacket.Builder()
                    .rawData(responseData)
                    .build();

            // Build UDP Header with swapped addresses
            UdpPacket responseUdp = new UdpPacket.Builder()
                    .srcPort(udpPacket.getHeader().getDstPort()) // Server Port -> Source
                    .dstPort(udpPacket.getHeader().getSrcPort()) // Phone Port -> Dest
                    .srcAddr(ipPacket.getHeader().getDstAddr())
                    .dstAddr(ipPacket.getHeader().getSrcAddr())
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true)
                    .payloadBuilder(payloadObj.getBuilder())
                    .build();

            // Build IP Header with swapped addresses
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
            sendToUI("RESPONSE: " + responseInfo);

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

    private String analyzeICMPv6(IpV6Packet ip) {
        try {
            IcmpV6CommonPacket icmp = ip.get(IcmpV6CommonPacket.class);
            String src = ip.getHeader().getSrcAddr().getHostAddress();
            String dst = ip.getHeader().getDstAddr().getHostAddress();

            int type = icmp.getHeader().getType().value();

            StringBuilder result = new StringBuilder();
            result.append(String.format("ICMPv6 | %s → %s | ", src, dst));
            result.append(getICMPv6TypeDescription(type));

            return result.toString();

        } catch (Exception e) {
            return String.format("ICMPv6 | %s → %s | Parse error",
                    ip.getHeader().getSrcAddr().getHostAddress(),
                    ip.getHeader().getDstAddr().getHostAddress());
        }
    }

    private String analyzeICMPv4(IpV4Packet ip) {
        try {
            IcmpV4CommonPacket icmp = ip.get(IcmpV4CommonPacket.class);
            String src = ip.getHeader().getSrcAddr().getHostAddress();
            String dst = ip.getHeader().getDstAddr().getHostAddress();

            int type = icmp.getHeader().getType().value();
            int code = icmp.getHeader().getCode().value();

            StringBuilder result = new StringBuilder();
            result.append(String.format("ICMPv4 | %s → %s | ", src, dst));
            result.append(getICMPv4TypeDescription(type, code));

            return result.toString();

        } catch (Exception e) {
            return String.format("ICMPv4 | %s → %s | Parse error",
                    ip.getHeader().getSrcAddr().getHostAddress(),
                    ip.getHeader().getDstAddr().getHostAddress());
        }
    }

    private String analyzeSSH(TcpPacket tcp) {
        try {
            if (tcp.getPayload() == null) {
                return null;
            }

            byte[] data = tcp.getPayload().getRawData();
            if (data.length < 4) {
                return null;
            }

            // SSH handshake commence par "SSH-"
            if (data[0] == 'S' && data[1] == 'S' && data[2] == 'H' && data[3] == '-') {
                StringBuilder version = new StringBuilder();
                for (int i = 0; i < Math.min(data.length, 50); i++) {
                    byte b = data[i];
                    if (b == '\r' || b == '\n') break;
                    version.append((char) b);
                }
                return version.toString();
            }

            return "Encrypted SSH";

        } catch (Exception e) {
            Log.e(TAG, "SSH Parsing error", e);
            return null;
        }
    }

    private String decodeDNS(UdpPacket udp) {
        if (udp.getPayload() == null) return "No Data";
        byte[] data = udp.getPayload().getRawData();
        if (data.length < 12) return "DNS Header too short";

        StringBuilder domain = new StringBuilder();
        int pos = 12;

        try {
            while (pos < data.length && data[pos] > 0) {
                int labelLength = data[pos];
                if (pos + labelLength + 1 > data.length) break;

                for (int i = 0; i < labelLength; i++) {
                    domain.append((char) data[pos + 1 + i]);
                }
                domain.append(".");
                pos += labelLength + 1;
            }
        } catch (Exception e) {
            return "DNS Parsing Error";
        }

        String query = domain.toString();
        return query.isEmpty() ? "DNS Query (Other)" : "Query: " + query;
    }

    private String decodeHTTP(TcpPacket tcp) {
        if (tcp.getPayload() == null) return "No Data";
        String data = new String(tcp.getPayload().getRawData());

        if (data.startsWith("GET") || data.startsWith("POST") || data.startsWith("HTTP")) {
            // On récupère la première ligne (ex: GET /index.html HTTP/1.1)
            String firstLine = data.split("\r\n")[0];

            // On cherche le header "Host:" pour savoir quel site est visité
            String host = "";
            for (String line : data.split("\r\n")) {
                if (line.startsWith("Host: ")) {
                    host = line.replace("Host: ", "");
                    break;
                }
            }
            return firstLine + (host.isEmpty() ? "" : " [Host: " + host + "]");
        }

        return "HTTP Data (Continuation/Binary)";
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

    private String decodeTelnet(TcpPacket tcp) {
        if (tcp.getPayload() == null) return "Empty Payload";

        byte[] data = tcp.getPayload().getRawData();
        if (data.length == 0) return "No Data";

        StringBuilder content = new StringBuilder();

        // We filter for printable ASCII to make it readable.
        for (byte b : data) {
            // Standard printable ASCII range (32-126)
            if (b >= 32 && b <= 126) {
                content.append((char) b);
            }
            // Handle Newlines (Enter key)
            else if (b == 10 || b == 13) {
                content.append("[Un]"); // Mark newlines visually
            }
            // Ignore Telnet Command Codes (usually start with 255 / 0xFF)
        }

        if (content.length() == 0) return "Binary/Control Data";

        return content.toString();
    }

    private String getICMPv4TypeDescription(int type, int code) {
        StringBuilder description = new StringBuilder();

        switch (type) {
            case 0:
                description.append("Echo Reply");
                break;
            case 3:
                description.append("Destination Unreachable");
                switch (code) {
                    case 0: description.append(" (Net)"); break;
                    case 1: description.append(" (Host)"); break;
                    case 2: description.append(" (Protocol)"); break;
                    case 3: description.append(" (Port)"); break;
                    case 4: description.append(" (Fragmentation)"); break;
                    case 5: description.append(" (Source Route)"); break;
                    case 6: description.append(" (Net Unknown)"); break;
                    case 7: description.append(" (Host Unknown)"); break;
                    case 9: description.append(" (Comms Prohibited)"); break;
                    case 10: description.append(" (Host Prohibited)"); break;
                    case 13: description.append(" (Comms Prohibited)"); break;
                }
                break;
            case 5:
                description.append("Redirect");
                break;
            case 8:
                description.append("Echo Request");
                break;
            case 11:
                description.append("Time Exceeded");
                description.append(code == 0 ? " (TTL)" : " (Fragment)");
                break;
            case 13:
                description.append("Timestamp Request");
                break;
            case 14:
                description.append("Timestamp Reply");
                break;
            case 17:
                description.append("Address Mask Request");
                break;
            case 18:
                description.append("Address Mask Reply");
                break;
            default:
                description.append(String.format("Type: %d, Code: %d", type, code));
        }

        return description.toString();
    }

    private String getICMPv6TypeDescription(int type) {
        switch (type) {
            case 128: return "Echo Request";
            case 129: return "Echo Reply";
            case 133: return "Router Solicitation";
            case 134: return "Router Advertisement";
            case 135: return "Neighbor Solicitation [NDP]";
            case 136: return "Neighbor Advertisement [NDP]";
            case 137: return "Redirect";
            default: return String.format("Type: %d", type);
        }
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

        if (udpExecutor != null) {
            udpExecutor.shutdownNow();
        }

        stopVpn();
    }
}

