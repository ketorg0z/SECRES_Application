package com.example.analyseurtrafic;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Locale;

public class VPN extends VpnService {

    // ============================================
    // CONSTANTES
    // ============================================

    public static final String ACTION_PACKET_RECEIVED = "com.example.analyseurtrafic.PACKET_RECEIVED";
    public static final String EXTRA_PACKET_INFO = "packet_info";

    private static final String TAG = "SecurityAnalyzerVPN";
    private static final int MAX_PACKET_SIZE = 65535;

    // ============================================
    // VARIABLES D'INSTANCE
    // ============================================

    private ParcelFileDescriptor vpnInterface = null;
    private Thread vpnThread;
    private volatile boolean isRunning = false;

    // Statistiques
    private int totalPackets = 0;
    private int arpPackets = 0;
    private int icmpPackets = 0;
    private int sshPackets = 0;
    private int suspiciousPackets = 0;

    // ============================================
    // MÉTHODES DU CYCLE DE VIE DU SERVICE
    // ============================================

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (vpnThread == null || !vpnThread.isAlive()) {
            isRunning = true;
            vpnThread = new Thread(this::runVpn, "VPN-Thread");
            vpnThread.start();
            Log.i(TAG, "Service VPN démarré");
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        stopVpn();
    }

    // ============================================
    // MÉTHODE PRINCIPALE VPN
    // ============================================

    private void runVpn() {
        FileInputStream in = null;
        FileOutputStream out = null;

        try {
            // 1. Configuration de l'interface VPN
            Builder builder = new Builder();
            builder.setSession("Security Traffic Analyzer");
            builder.setMtu(1500);
            builder.addAddress("10.0.0.2", 24);
            builder.addRoute("0.0.0.0", 0);
            builder.addDnsServer("8.8.8.8");
            builder.addDnsServer("8.8.4.4");

            // 2. Établissement de l'interface VPN
            vpnInterface = builder.establish();
            if (vpnInterface == null) {
                Log.e(TAG, "Échec de l'établissement de l'interface VPN");
                return;
            }

            // 3. Initialisation des flux
            in = new FileInputStream(vpnInterface.getFileDescriptor());
            out = new FileOutputStream(vpnInterface.getFileDescriptor());

            // 4. Boucle principale d'analyse
            byte[] buffer = new byte[MAX_PACKET_SIZE];
            Log.i(TAG, "Démarrage de l'analyse du trafic...");

            while (isRunning && !Thread.interrupted()) {
                int length = in.read(buffer);
                if (length > 0) {
                    totalPackets++;

                    // Analyse du paquet
                    String analysis = analyzePacket(buffer, length);

                    // Forward du paquet
                    out.write(buffer, 0, length);

                    // Envoi à l'interface utilisateur
                    if (analysis != null && !analysis.isEmpty()) {
                        sendToUI(analysis);
                    }

                    // Log périodique
                    if (totalPackets % 100 == 0) {
                        logStatistics();
                    }
                }
            }

        } catch (IOException e) {
            if (isRunning) {
                Log.e(TAG, "Erreur VPN", e);
            }
        } catch (Exception e) {
            Log.e(TAG, "Erreur inattendue", e);
        } finally {
            closeResources(in, out);
            stopVpn();
        }
    }

    // ============================================
    // MÉTHODES D'ANALYSE DES PAQUETS (HIGH-LEVEL)
    // ============================================

    /**
     * Point d'entrée principal pour l'analyse des paquets
     */
    private String analyzePacket(byte[] data, int length) {
        try {
            if (length < 20) {
                return String.format(Locale.getDefault(), "Small packet: %d bytes", length);
            }

            // Détection de la version IP (4 bits de poids fort du premier octet)
            int version = (data[0] >> 4) & 0x0F;

            switch (version) {
                case 4: // IPv4
                    return analyzeIPv4Packet(data, length);

                case 6: // IPv6
                    return analyzeIPv6Packet(data, length);

                default:
                    return analyzeNonIPPacket(data, length);
            }
        } catch (Exception e) {
            Log.e(TAG, "Erreur d'analyse du paquet", e);
            return "Analysis error";
        }
    }

    /**
     * Analyse d'un paquet IPv4
     */
    private String analyzeIPv4Packet(byte[] data, int length) throws Exception {
        IpV4Packet ip = IpV4Packet.newPacket(data, 0, length);
        String src = ip.getHeader().getSrcAddr().getHostAddress();
        String dst = ip.getHeader().getDstAddr().getHostAddress();
        int protocol = ip.getHeader().getProtocol().value();

        switch (protocol) {
            case 1: // ICMP
                icmpPackets++;
                return analyzeICMPv4(ip);

            case 6: // TCP
                return analyzeTCP(ip, src, dst);

            case 17: // UDP
                return analyzeUDP(ip, src, dst);

            default:
                return String.format(Locale.getDefault(), "IPv4 | Proto: %d | %s → %s",
                        protocol, src, dst);
        }
    }

    /**
     * Analyse d'un paquet IPv6
     */
    private String analyzeIPv6Packet(byte[] data, int length) throws Exception {
        IpV6Packet ip = IpV6Packet.newPacket(data, 0, length);
        String src = ip.getHeader().getSrcAddr().getHostAddress();
        String dst = ip.getHeader().getDstAddr().getHostAddress();
        int protocol = ip.getHeader().getNextHeader().value();

        switch (protocol) {
            case 58: // ICMPv6
                icmpPackets++;
                return analyzeICMPv6(ip);

            case 6: // TCP
                return analyzeTCP(ip, src, dst);

            case 17: // UDP
                return analyzeUDP(ip, src, dst);

            default:
                return String.format(Locale.getDefault(), "IPv6 | Proto: %d | %s → %s",
                        protocol, src, dst);
        }
    }

    /**
     * Analyse d'un paquet non-IP (ARP, etc.)
     */
    private String analyzeNonIPPacket(byte[] data, int length) {
        // Vérification pour ARP
        if (length >= 8) {
            int hardwareType = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
            int protocolType = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);

            if (hardwareType == 1 && protocolType == 0x0800) {
                arpPackets++;
                try {
                    ArpPacket arp = ArpPacket.newPacket(data, 0, length);
                    return analyzeARPPacket(arp);
                } catch (Exception ignored) {
                    return "ARP (raw)";
                }
            }
        }

        return String.format(Locale.getDefault(), "Unknown | Length: %d bytes", length);
    }

    // ============================================
    // ANALYSE DES PROTOCOLES SPÉCIFIQUES
    // ============================================

    /**
     * Analyse ICMPv4
     */
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

            // Détection de scans ICMP
            if ((type == 8 || type == 13 || type == 17) &&
                    !src.startsWith("192.168.") && !src.startsWith("10.")) {
                result.append(" [External Scan]");
            }

            return result.toString();

        } catch (Exception e) {
            return String.format("ICMPv4 | %s → %s | Parse error",
                    ip.getHeader().getSrcAddr().getHostAddress(),
                    ip.getHeader().getDstAddr().getHostAddress());
        }
    }

    /**
     * Analyse ICMPv6
     */
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

    /**
     * Analyse ARP
     */
    private String analyzeARPPacket(ArpPacket arp) {
        ArpOperation operation = arp.getHeader().getOperation();
        String srcIp = arp.getHeader().getSrcProtocolAddr().getHostAddress();
        String dstIp = arp.getHeader().getDstProtocolAddr().getHostAddress();
        String srcMac = formatMacAddress(arp.getHeader().getSrcHardwareAddr());
        String dstMac = formatMacAddress(arp.getHeader().getDstHardwareAddr());

        String opStr;
        switch (operation.value()) {
            case 1:
                opStr = "REQUEST";
                break;
            case 2:
                opStr = "REPLY";
                break;
            default:
                opStr = "OP_" + operation.value();
        }

        return String.format(Locale.getDefault(), "ARP | %s | %s (%s) → %s (%s)",
                opStr, srcIp, srcMac, dstIp, dstMac);
    }

    // ============================================
    // ANALYSE TCP ET UDP
    // ============================================

    /**
     * Analyse TCP (IPv4 et IPv6)
     */
    private String analyzeTCP(IpV4Packet ip, String src, String dst) {
        try {
            TcpPacket tcp = ip.get(TcpPacket.class);
            int sport = tcp.getHeader().getSrcPort().valueAsInt();
            int dport = tcp.getHeader().getDstPort().valueAsInt();
            return analyzeTCPCommon(src, dst, sport, dport, tcp, "IPv4");
        } catch (Exception e) {
            return String.format("TCP/IPv4 | %s → %s | Error", src, dst);
        }
    }

    private String analyzeTCP(IpV6Packet ip, String src, String dst) {
        try {
            TcpPacket tcp = ip.get(TcpPacket.class);
            int sport = tcp.getHeader().getSrcPort().valueAsInt();
            int dport = tcp.getHeader().getDstPort().valueAsInt();
            return analyzeTCPCommon(src, dst, sport, dport, tcp, "IPv6");
        } catch (Exception e) {
            return String.format("TCP/IPv6 | %s → %s | Error", src, dst);
        }
    }

    private String analyzeTCPCommon(String src, String dst, int sport, int dport,
                                    TcpPacket tcp, String ipVersion) {
        String protocol = identifyProtocolByPort(sport, dport);
        if (protocol == null) {
            return String.format(Locale.getDefault(), "%s | TCP | %s:%d → %s:%d",
                    ipVersion, src, sport, dst, dport);
        }

        StringBuilder result = new StringBuilder();
        result.append(String.format(Locale.getDefault(), "%s | TCP | %s | %s:%d → %s:%d",
                ipVersion, protocol, src, sport, dst, dport));

        // Analyse spécifique au protocole
        performProtocolSpecificAnalysis(protocol, tcp, result);

        // Flags TCP
        appendTCPFlags(tcp, result);

        // Détection de scans
        detectTCPScan(tcp, dport, result);

        return result.toString();
    }

    /**
     * Analyse UDP (IPv4 et IPv6)
     */
    private String analyzeUDP(IpV4Packet ip, String src, String dst) {
        try {
            UdpPacket udp = ip.get(UdpPacket.class);
            int sport = udp.getHeader().getSrcPort().valueAsInt();
            int dport = udp.getHeader().getDstPort().valueAsInt();
            return analyzeUDPCommon(src, dst, sport, dport, udp, "IPv4");
        } catch (Exception e) {
            return String.format("UDP/IPv4 | %s → %s | Error", src, dst);
        }
    }

    private String analyzeUDP(IpV6Packet ip, String src, String dst) {
        try {
            UdpPacket udp = ip.get(UdpPacket.class);
            int sport = udp.getHeader().getSrcPort().valueAsInt();
            int dport = udp.getHeader().getDstPort().valueAsInt();
            return analyzeUDPCommon(src, dst, sport, dport, udp, "IPv6");
        } catch (Exception e) {
            return String.format("UDP/IPv6 | %s → %s | Error", src, dst);
        }
    }

    private String analyzeUDPCommon(String src, String dst, int sport, int dport,
                                    UdpPacket udp, String ipVersion) {
        String protocol = identifyProtocolByPort(sport, dport);
        if (protocol == null) {
            return String.format(Locale.getDefault(), "%s | UDP | %s:%d → %s:%d",
                    ipVersion, src, sport, dst, dport);
        }

        StringBuilder result = new StringBuilder();
        result.append(String.format(Locale.getDefault(), "%s | UDP | %s | %s:%d → %s:%d",
                ipVersion, protocol, src, sport, dst, dport));

        // Analyse spécifique au protocole
        performUDPProtocolAnalysis(protocol, udp, result);

        return result.toString();
    }

    // ============================================
    // MÉTHODES D'ANALYSE SPÉCIFIQUES AUX PROTOCOLES
    // ============================================

    /**
     * Identification du protocole par port
     */
    private String identifyProtocolByPort(int sport, int dport) {
        // Priorité au port de destination
        if (dport == 22 || sport == 22) return "SSH";
        if (dport == 23 || sport == 23) return "TELNET";
        if (dport == 161 || sport == 161 || dport == 162 || sport == 162) return "SNMP";
        if (dport == 3389 || sport == 3389) return "RDP";
        if (dport == 389 || sport == 389) return "LDAP";
        if (dport == 123 || sport == 123) return "NTP";
        if (dport == 80 || sport == 80) return "HTTP";
        if (dport == 443 || sport == 443) return "HTTPS";
        if (dport == 53 || sport == 53) return "DNS";
        return null;
    }

    /**
     * Analyse spécifique pour les protocoles TCP
     */
    private void performProtocolSpecificAnalysis(String protocol, TcpPacket tcp, StringBuilder result) {
        switch (protocol) {
            case "SSH":
                sshPackets++;
                String sshInfo = analyzeSSH(tcp);
                if (sshInfo != null) {
                    result.append(" | ").append(sshInfo);
                }
                break;

            case "TELNET":
                result.append(" [INSECURE]");
                suspiciousPackets++;
                break;

            case "RDP":
                if (analyzeRDP(tcp)) {
                    result.append(" [Weak Encryption?]");
                }
                break;
        }
    }

    /**
     * Analyse spécifique pour les protocoles UDP
     */
    private void performUDPProtocolAnalysis(String protocol, UdpPacket udp, StringBuilder result) {
        switch (protocol) {
            case "DNS":
                String dnsInfo = analyzeDNS(udp);
                if (dnsInfo != null) {
                    result.append(" | ").append(dnsInfo);
                }
                break;

            case "SNMP":
                if (analyzeSNMP(udp)) {
                    result.append(" [Insecure v1/v2c]");
                    suspiciousPackets++;
                }
                break;

            case "NTP":
                String ntpInfo = analyzeNTP(udp);
                if (ntpInfo != null) {
                    result.append(" | ").append(ntpInfo);
                }
                break;
        }
    }

    // ============================================
    // MÉTHODES D'ANALYSE DÉTAILLÉE DES PROTOCOLES
    // ============================================

    /**
     * Analyse SSH
     */
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
            Log.e(TAG, "Erreur d'analyse SSH", e);
            return null;
        }
    }

    /**
     * Analyse RDP
     */
    private boolean analyzeRDP(TcpPacket tcp) {
        try {
            if (tcp.getPayload() == null) {
                return false;
            }

            byte[] data = tcp.getPayload().getRawData();
            if (data.length < 8) {
                return false;
            }

            // Détection basique de RDP non sécurisé
            for (int i = 0; i < Math.min(data.length, 20); i++) {
                if (data[i] == 'R' && i + 2 < data.length) {
                    if (data[i + 1] == 'D' && data[i + 2] == 'P') {
                        if (i + 10 < data.length) {
                            int version = data[i + 3] & 0xFF;
                            return version < 10; // Version ancienne
                        }
                    }
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Erreur d'analyse RDP", e);
        }
        return false;
    }

    /**
     * Analyse DNS
     */
    private String analyzeDNS(UdpPacket udp) {
        try {
            if (udp.getPayload() == null) {
                return null;
            }

            byte[] data = udp.getPayload().getRawData();
            if (data.length < 12) {
                return null;
            }

            int flags = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
            int qdCount = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
            int anCount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);

            boolean isResponse = (flags & 0x8000) != 0;
            int opcode = (flags >> 11) & 0x0F;

            String opcodeStr;
            switch (opcode) {
                case 0: opcodeStr = "QUERY"; break;
                case 1: opcodeStr = "IQUERY"; break;
                case 2: opcodeStr = "STATUS"; break;
                default: opcodeStr = "OP" + opcode;
            }

            StringBuilder result = new StringBuilder();
            result.append(isResponse ? "Response" : "Query");
            result.append(" | ").append(opcodeStr);
            result.append(" | QD:").append(qdCount);
            result.append(" AN:").append(anCount);

            return result.toString();

        } catch (Exception e) {
            Log.e(TAG, "Erreur d'analyse DNS", e);
            return null;
        }
    }

    /**
     * Analyse SNMP
     */
    private boolean analyzeSNMP(UdpPacket udp) {
        try {
            if (udp.getPayload() == null) {
                return false;
            }

            byte[] data = udp.getPayload().getRawData();
            if (data.length < 4 || data[0] != 0x30) {
                return false;
            }

            // Chercher la version SNMP (v1=0, v2c=1, v3=3)
            for (int i = 1; i < Math.min(data.length, 10); i++) {
                if (data[i] == 0x02 && i + 2 < data.length) { // INTEGER type
                    int version = data[i + 2] & 0xFF;
                    return version == 0 || version == 1; // v1 ou v2c = non sécurisé
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Erreur d'analyse SNMP", e);
        }
        return false;
    }

    /**
     * Analyse NTP
     */
    private String analyzeNTP(UdpPacket udp) {
        try {
            if (udp.getPayload() == null) {
                return null;
            }

            byte[] data = udp.getPayload().getRawData();
            if (data.length < 48) {
                return null;
            }

            int firstByte = data[0] & 0xFF;
            int version = (firstByte >> 3) & 0x07;
            int mode = firstByte & 0x07;

            String modeStr;
            switch (mode) {
                case 1: modeStr = "Symmetric Active"; break;
                case 2: modeStr = "Symmetric Passive"; break;
                case 3: modeStr = "Client"; break;
                case 4: modeStr = "Server"; break;
                case 5: modeStr = "Broadcast"; break;
                case 6: modeStr = "Control"; break;
                case 7: modeStr = "Private"; break;
                default: modeStr = "Unknown";
            }

            return String.format(Locale.getDefault(), "v%d | %s", version, modeStr);

        } catch (Exception e) {
            Log.e(TAG, "Erreur d'analyse NTP", e);
            return null;
        }
    }

    // ============================================
    // MÉTHODES UTILITAIRES
    // ============================================

    /**
     * Formate une adresse MAC
     */
    private String formatMacAddress(MacAddress mac) {
        try {
            byte[] bytes = mac.getAddress();
            if (bytes.length >= 6) {
                return String.format(Locale.getDefault(), "%02X:%02X:%02X:%02X:%02X:%02X",
                        bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF,
                        bytes[3] & 0xFF, bytes[4] & 0xFF, bytes[5] & 0xFF);
            }
        } catch (Exception e) {
            Log.e(TAG, "Erreur de formatage d'adresse MAC", e);
        }
        return "00:00:00:00:00:00";
    }

    /**
     * Obtient la description d'un type ICMPv4
     */
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
                suspiciousPackets++;
                description.append(" [SUSPICIOUS]");
                break;
            case 8:
                description.append("Echo Request");
                if (icmpPackets > 1000) {
                    description.append(" [Possible Flood]");
                    suspiciousPackets++;
                }
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
                description.append(String.format(Locale.getDefault(), "Type: %d, Code: %d", type, code));
        }

        return description.toString();
    }

    /**
     * Obtient la description d'un type ICMPv6
     */
    private String getICMPv6TypeDescription(int type) {
        switch (type) {
            case 128: return "Echo Request";
            case 129: return "Echo Reply";
            case 133: return "Router Solicitation";
            case 134: return "Router Advertisement";
            case 135: return "Neighbor Solicitation [NDP]";
            case 136: return "Neighbor Advertisement [NDP]";
            case 137:
                suspiciousPackets++;
                return "Redirect [SUSPICIOUS]";
            default: return String.format(Locale.getDefault(), "Type: %d", type);
        }
    }

    /**
     * Ajoute les flags TCP au résultat
     */
    private void appendTCPFlags(TcpPacket tcp, StringBuilder result) {
        StringBuilder flags = new StringBuilder();
        if (tcp.getHeader().getSyn()) flags.append("S");
        if (tcp.getHeader().getAck()) flags.append("A");
        if (tcp.getHeader().getFin()) flags.append("F");
        if (tcp.getHeader().getRst()) flags.append("R");
        if (tcp.getHeader().getPsh()) flags.append("P");
        if (tcp.getHeader().getUrg()) flags.append("U");

        if (flags.length() > 0) {
            result.append(" | Flags: ").append(flags);
        }
    }

    /**
     * Détecte les scans TCP
     */
    private void detectTCPScan(TcpPacket tcp, int dport, StringBuilder result) {
        if (tcp.getHeader().getSyn() && !tcp.getHeader().getAck() && dport < 1024) {
            result.append(" [SYN Scan]");
            suspiciousPackets++;
        }
    }

    /**
     * Envoie un message à l'interface utilisateur
     */
    private void sendToUI(String text) {
        try {
            Intent intent = new Intent(ACTION_PACKET_RECEIVED);
            intent.putExtra(EXTRA_PACKET_INFO, text);
            LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
        } catch (Exception e) {
            Log.e(TAG, "Erreur d'envoi à l'UI", e);
        }
    }

    /**
     * Arrête le service VPN
     */
    private void stopVpn() {
        isRunning = false;

        if (vpnThread != null) {
            vpnThread.interrupt();
            try {
                vpnThread.join(1000);
            } catch (InterruptedException e) {
                Log.w(TAG, "Interruption lors de l'arrêt du thread VPN");
                Thread.currentThread().interrupt();
            }
            vpnThread = null;
        }

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException e) {
                Log.e(TAG, "Erreur de fermeture de l'interface VPN", e);
            }
            vpnInterface = null;
        }

        Log.i(TAG, "Service VPN arrêté");
    }

    /**
     * Ferme les ressources
     */
    private void closeResources(FileInputStream in, FileOutputStream out) {
        try {
            if (in != null) in.close();
            if (out != null) out.close();
        } catch (IOException e) {
            Log.e(TAG, "Erreur de fermeture des flux", e);
        }
    }

    /**
     * Log les statistiques
     */
    private void logStatistics() {
        Log.d(TAG, String.format(Locale.getDefault(),
                "Paquets traités: %d, ARP: %d, ICMP: %d, Suspects: %d",
                totalPackets, arpPackets, icmpPackets, suspiciousPackets));
    }
}