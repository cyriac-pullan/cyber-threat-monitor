import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../providers/threat_provider.dart';

class AlertsScreen extends StatelessWidget {
  const AlertsScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Security Alerts'),
      ),
      body: Consumer<ThreatProvider>(
        builder: (context, threatProvider, child) {
          if (threatProvider.isLoading) {
            return const Center(child: CircularProgressIndicator());
          }

          final alerts = threatProvider.alerts;

          if (alerts.isEmpty) {
            return const Center(
              child: Text('No alerts at this time'),
            );
          }

          return ListView.builder(
            itemCount: alerts.length,
            itemBuilder: (context, index) {
              final alert = alerts[index];
              return Card(
                margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                child: ListTile(
                  title: Text(alert['message'] ?? 'Unknown alert'),
                  subtitle: Text(alert['timestamp'] ?? ''),
                  trailing: IconButton(
                    icon: const Icon(Icons.check),
                    onPressed: () {
                      threatProvider.acknowledgeAlert(alert['id']);
                    },
                  ),
                ),
              );
            },
          );
        },
      ),
    );
  }
} 