package com.example.analyseurtrafic;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;


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
            Builder builder = new Builder();
            builder.setSession("AnalyseurTrafic");
            builder.addAddress("10.0.0.2", 24);
            builder.addRoute("0.0.0.0", 0);


            // 1. Éviter la boucle infinie : l'app ne s'analyse pas elle-même
            builder.addDisallowedApplication(getPackageName());

            // 2. Ajouter un DNS pour que le navigateur sache où envoyer les requêtes
            builder.addDnsServer("8.8.8.8");

            // 3. Taille de paquet standard
            builder.setMtu(1500);
            // ------------------------------

            vpnInterface = builder.establish();
            if (vpnInterface == null) return;

            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());

            byte[] buffer = new byte[32767];

            while (!Thread.interrupted()) {
                int length = in.read(buffer);
                if (length > 0) {
                    // Analyse du paquet
                    String info = defineIPVersion(buffer, length);
                    sendToUI(info);

                    out.write(buffer, 0, length);
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
        try {
            int protocol = ip.getHeader().getProtocol().value();
            String src = ip.getHeader().getSrcAddr().getHostAddress();
            String dst = ip.getHeader().getDstAddr().getHostAddress();

            // TCP
            if (protocol == 6 && ip.contains(TcpPacket.class)) {
                TcpPacket tcp = ip.get(TcpPacket.class);
                int sport = tcp.getHeader().getSrcPort().valueAsInt();
                int dport = tcp.getHeader().getDstPort().valueAsInt();

                if (sport == 80 || dport == 80) {
                    return "IPv4 | HTTP | " + src + " → " + dst + " | " + decodeHTTP(tcp);
                }
                return "IPv4 | TCP | " + src + ":" + sport + " → " + dst + ":" + dport + identifyAppProtocol(dport);
            }

            // UDP
            else if (protocol == 17 && ip.contains(UdpPacket.class)) {
                UdpPacket udp = ip.get(UdpPacket.class);
                int sport = udp.getHeader().getSrcPort().valueAsInt();
                int dport = udp.getHeader().getDstPort().valueAsInt();

                if (sport == 53 || dport == 53) {
                    return "IPv4 | DNS | " + src + " → " + dst + " | " + decodeDNS(udp);
                }
                if (sport == 123 || dport == 123) {
                    return "IPv4 | NTP | " + src + " → " + dst + " | " + decodeNTP(udp);
                }
                return "IPv4 | UDP | " + src + ":" + sport + " → " + dst + ":" + dport + identifyAppProtocol(dport);
            }

            return "IPv4 | Protocole " + protocol + " | " + src + " → " + dst;
        } catch (Exception e) {
            return "Erreur Parsing IPv4";
        }
    }


    private String parseIPv6(IpV6Packet ip) {
        try {
            // En IPv6, on regarde le champ "Next Header"
            int nextHeader = ip.getHeader().getNextHeader().value();
            String src = ip.getHeader().getSrcAddr().getHostAddress();
            String dst = ip.getHeader().getDstAddr().getHostAddress();

            // 1. Gestion du TCP
            if (nextHeader == 6 && ip.contains(TcpPacket.class)) {
                TcpPacket tcp = ip.get(TcpPacket.class);
                int sport = tcp.getHeader().getSrcPort().valueAsInt();
                int dport = tcp.getHeader().getDstPort().valueAsInt();

                if (sport == 80 || dport == 80) {
                    return "IPv6 | HTTP | " + src + " → " + dst + " | " + decodeHTTP(tcp);
                }

                if (sport == 389 || dport == 389) {
                    return "IPv6 | LDAP | " + src + " → " + dst + " | " + decodeTCP(tcp);
                }

                return "IPv6 | TCP | " + src + ":" + sport + " → " + dst + ":" + dport + identifyAppProtocol(dport);
            }

            // 2. Gestion du UDP
            else if (nextHeader == 17 && ip.contains(UdpPacket.class)) {
                UdpPacket udp = ip.get(UdpPacket.class);
                int sport = udp.getHeader().getSrcPort().valueAsInt();
                int dport = udp.getHeader().getDstPort().valueAsInt();

                if (sport == 53 || dport == 53) {
                    return "IPv6 | DNS | " + src + " → " + dst + " | " + decodeDNS(udp);
                }

                if (sport == 123 || dport == 123) {
                    return "IPv6 | NTP | " + src + " → " + dst + " | " + decodeNTP(udp);
                }

                return "IPv6 | UDP | " + src + ":" + sport + " → " + dst + ":" + dport + identifyAppProtocol(dport);
            }

            // 3. Gestion ICMPv6
            else if (nextHeader == 58) {
                return "IPv6 | ICMPv6 (Ping/Neighbor Disc.) | " + src + " → " + dst;
            }

            return "IPv6 | NextHeader: " + nextHeader + " | " + src + " → " + dst;

        } catch (Exception e) {
            Log.e(TAG, "Erreur parsing IPv6", e);
            return "IPv6 Parsing Error";
        }
    }

    private String identifyAppProtocol(int port) {
        if (port == 80) return " (HTTP)";
        if (port == 443) return " (HTTPS)";
        if (port == 53) return " (DNS)";
        if (port == 123) return " (NTP)";
        if (port == 389) return " (LDAP)";
        return "";
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




    @Override
    public void onDestroy() {
        super.onDestroy();
        stopVpn();
    }
}

