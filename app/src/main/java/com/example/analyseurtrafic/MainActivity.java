package com.example.analyseurtrafic;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.SearchView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.util.ArrayList;
import java.util.Locale;

public class MainActivity extends AppCompatActivity {

    private static final int VPN_REQUEST_CODE = 0;

    // 🔹 UI
    private ListView packetListView;
    private Button pauseButton;
    private SearchView searchView;

    // 🔹 Data
    private ArrayList<String> allPackets;
    private ArrayList<String> filteredPackets;
    private ArrayAdapter<String> packetAdapter;

    // 🔹 State
    private boolean isPaused = false;
    private String currentQuery = "";

    // 🔹 Receiver VPN → UI
    private final BroadcastReceiver packetReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent == null) return;

            if (VPN.ACTION_PACKET_RECEIVED.equals(intent.getAction())) {

                String packetInfo = intent.getStringExtra(VPN.EXTRA_PACKET_INFO);
                if (packetInfo == null) return;

                // Toujours stocker le paquet
                allPackets.add(0, packetInfo);

                // Limite mémoire
                if (allPackets.size() > 2000) {
                    allPackets.remove(allPackets.size() - 1);
                }

                // Si UI en pause → ne pas rafraîchir
                if (isPaused) return;

                // Appliquer le filtre de recherche
                filterPackets();

                // Auto-scroll uniquement si l'utilisateur est en haut
                if (packetListView.getFirstVisiblePosition() == 0) {
                    packetListView.setSelection(0);
                }
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 🔹 UI init
        packetListView = findViewById(R.id.packet_list);
        pauseButton = findViewById(R.id.pause_btn);
        searchView = findViewById(R.id.search_view);

        // 🔹 Data init
        allPackets = new ArrayList<>();
        filteredPackets = new ArrayList<>();

        packetAdapter = new ArrayAdapter<>(
                this,
                android.R.layout.simple_list_item_1,
                filteredPackets
        );
        packetListView.setAdapter(packetAdapter);

        // 🔹 Pause / Resume UI
        pauseButton.setOnClickListener(v -> {
            isPaused = !isPaused;
            pauseButton.setText(isPaused ? "Resume UI" : "Pause UI");

            // Si on reprend → rafraîchir la vue
            if (!isPaused) {
                filterPackets();
            }
        });

        // 🔹 Recherche
        setupSearch();

        // 🔹 Démarrage VPN
        Intent vpnIntent = VpnService.prepare(getApplicationContext());
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE);
        } else {
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
        }
    }

    // 🔍 SearchView logic
    private void setupSearch() {
        searchView.setOnQueryTextListener(new SearchView.OnQueryTextListener() {
            @Override
            public boolean onQueryTextSubmit(String query) {
                return false;
            }

            @Override
            public boolean onQueryTextChange(String newText) {
                currentQuery = newText.toLowerCase(Locale.ROOT);
                filterPackets();
                return true;
            }
        });
    }

    // 🔍 Filtrage des paquets
    private void filterPackets() {
        filteredPackets.clear();

        if (currentQuery.isEmpty()) {
            filteredPackets.addAll(allPackets);
        } else {
            for (String packet : allPackets) {
                if (packet.toLowerCase(Locale.ROOT).contains(currentQuery)) {
                    filteredPackets.add(packet);
                }
            }
        }

        packetAdapter.notifyDataSetChanged();
    }

    // 🔐 VPN Permission result
    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            Intent intent = new Intent(this, VPN.class);
            startService(intent);
        } else {
            allPackets.add(0, "❌ VPN permission not granted");
            filterPackets();
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
