import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../providers/threat_provider.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Cyber Threat Monitor'),
      ),
      body: Consumer<ThreatProvider>(
        builder: (context, threatProvider, child) {
          if (threatProvider.isLoading) {
            return const Center(child: CircularProgressIndicator());
          }

          final systemStatus = threatProvider.systemStatus;
          final riskAssessment = threatProvider.riskAssessment;

          return SingleChildScrollView(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildStatusCard(systemStatus),
                const SizedBox(height: 16),
                _buildRiskAssessmentCard(riskAssessment),
                const SizedBox(height: 16),
                _buildRecentAlertsCard(threatProvider.alerts),
              ],
            ),
          );
        },
      ),
    );
  }

  Widget _buildStatusCard(Map<String, dynamic> status) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'System Status',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            Text('Status: ${status['status'] ?? 'Unknown'}'),
            Text('Blocked IPs: ${status['blocked_ips'] ?? 0}'),
            Text('Recent Alerts: ${status['recent_alerts'] ?? 0}'),
          ],
        ),
      ),
    );
  }

  Widget _buildRiskAssessmentCard(Map<String, dynamic> assessment) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Risk Assessment',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            Text('High Risk Users: ${assessment['high_risk_users']?.length ?? 0}'),
            Text('High Risk IPs: ${assessment['high_risk_ips']?.length ?? 0}'),
          ],
        ),
      ),
    );
  }

  Widget _buildRecentAlertsCard(List<dynamic> alerts) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Recent Alerts',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            if (alerts.isEmpty)
              const Text('No recent alerts')
            else
              ListView.builder(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                itemCount: alerts.length > 5 ? 5 : alerts.length,
                itemBuilder: (context, index) {
                  final alert = alerts[index];
                  return ListTile(
                    title: Text(alert['message'] ?? 'Unknown alert'),
                    subtitle: Text(alert['timestamp'] ?? ''),
                  );
                },
              ),
          ],
        ),
      ),
    );
  }
} 