import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../providers/threat_provider.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
      ),
      body: Consumer<ThreatProvider>(
        builder: (context, threatProvider, child) {
          return ListView(
            padding: const EdgeInsets.all(16.0),
            children: [
              _buildNotificationSettings(),
              const Divider(),
              _buildSystemSettings(),
            ],
          );
        },
      ),
    );
  }

  Widget _buildNotificationSettings() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Notification Settings',
          style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 16),
        SwitchListTile(
          title: const Text('High Risk Alerts'),
          subtitle: const Text('Receive notifications for high-risk threats'),
          value: true,
          onChanged: (value) {
            // TODO: Implement notification settings
          },
        ),
        SwitchListTile(
          title: const Text('Medium Risk Alerts'),
          subtitle: const Text('Receive notifications for medium-risk threats'),
          value: true,
          onChanged: (value) {
            // TODO: Implement notification settings
          },
        ),
        SwitchListTile(
          title: const Text('Low Risk Alerts'),
          subtitle: const Text('Receive notifications for low-risk threats'),
          value: false,
          onChanged: (value) {
            // TODO: Implement notification settings
          },
        ),
      ],
    );
  }

  Widget _buildSystemSettings() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'System Settings',
          style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 16),
        ListTile(
          title: const Text('Server URL'),
          subtitle: const Text('http://localhost:8501'),
          trailing: const Icon(Icons.edit),
          onTap: () {
            // TODO: Implement server URL editing
          },
        ),
        ListTile(
          title: const Text('WebSocket URL'),
          subtitle: const Text('ws://localhost:8765'),
          trailing: const Icon(Icons.edit),
          onTap: () {
            // TODO: Implement WebSocket URL editing
          },
        ),
      ],
    );
  }
} 