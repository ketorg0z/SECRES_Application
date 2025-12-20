package com.example.analyseurtrafic;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.util.ArrayList;

public class MainActivity extends AppCompatActivity {

    private static final int VPN_REQUEST_CODE = 0;

    private ListView packetListView;
    private ArrayAdapter<String> packetAdapter;
    private final ArrayList<String> packetList = new ArrayList<>();

    private final BroadcastReceiver packetReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent != null && VPN.ACTION_PACKET_RECEIVED.equals(intent.getAction())) {
                String packetInfo = intent.getStringExtra(VPN.EXTRA_PACKET_INFO);
                if (packetInfo != null) {
                    runOnUiThread(() -> addPacketToList(packetInfo));
                }
            }
        }

        private void addPacketToList(String packetInfo) {
            // Mettre en évidence selon le type de paquet
            String displayInfo;
            if (packetInfo.contains("[SUSPICIOUS]") || packetInfo.contains("[SPOOFING")) {
                displayInfo = "🚨 " + packetInfo;
            } else if (packetInfo.contains("[INSECURE]") || packetInfo.contains("[Weak")) {
                displayInfo = "⚠️ " + packetInfo;
            } else if (packetInfo.contains("ARP")) {
                displayInfo = "🔗 " + packetInfo;
            } else if (packetInfo.contains("ICMP")) {
                displayInfo = "📡 " + packetInfo;
            } else if (packetInfo.contains("SSH") || packetInfo.contains("HTTPS")) {
                displayInfo = "🔐 " + packetInfo;
            } else {
                displayInfo = packetInfo;
            }

            packetList.add(0, displayInfo);

            // Limiter la taille de la liste
            if (packetList.size() > 200) {
                packetList.remove(packetList.size() - 1);
            }

            packetAdapter.notifyDataSetChanged();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        packetListView = findViewById(R.id.packet_list);
        packetAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, packetList);
        packetListView.setAdapter(packetAdapter);

        Toast.makeText(this, "Démarrage de l'analyse VPN...",
                Toast.LENGTH_LONG).show();

        startVpnService();
    }

    private void startVpnService() {
        Intent vpnIntent = VpnService.prepare(getApplicationContext());
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
        } else {
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                Intent intent = new Intent(this, VPN.class);
                startService(intent);
                Toast.makeText(this, "VPN actif - Analyse en cours...",
                        Toast.LENGTH_SHORT).show();
            } else {
                packetList.add(0, "❌ Permission VPN refusée");
                packetAdapter.notifyDataSetChanged();
                Toast.makeText(this, "Permission VPN requise",
                        Toast.LENGTH_LONG).show();
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        LocalBroadcastManager.getInstance(this).registerReceiver(
                packetReceiver,
                new IntentFilter(VPN.ACTION_PACKET_RECEIVED)
        );
    }

    @Override
    protected void onPause() {
        super.onPause();
        LocalBroadcastManager.getInstance(this).unregisterReceiver(packetReceiver);
    }
}