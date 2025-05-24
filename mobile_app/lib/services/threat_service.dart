import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class ThreatService {
  final String baseUrl = 'http://192.168.73.118:8501';  // Your actual IP
  final storage = const FlutterSecureStorage();
  WebSocketChannel? _channel;
  
  Future<void> connectWebSocket(Function(dynamic) onMessage) async {
    print('Attempting to connect to WebSocket...');
    final wsUrl = Uri.parse('ws://192.168.73.118:8765/ws');  // Your actual IP
    print('WebSocket URL: $wsUrl');
    
    try {
      _channel = WebSocketChannel.connect(wsUrl);
      print('WebSocket connected successfully');
      
      _channel!.stream.listen(
        (message) {
          print('Received WebSocket message: $message');
          onMessage(jsonDecode(message));
        },
        onError: (error) {
          print('WebSocket Error: $error');
        },
        onDone: () {
          print('WebSocket Connection Closed');
        },
      );
    } catch (e) {
      print('Failed to connect to WebSocket: $e');
    }
  }
  
  Future<Map<String, dynamic>> getRiskAssessment() async {
    try {
      print('Fetching risk assessment from: $baseUrl/api/risk-assessment');
      final response = await http.get(Uri.parse('$baseUrl/api/risk-assessment'));
      print('Risk assessment response status: ${response.statusCode}');
      print('Risk assessment response body: ${response.body}');
      
      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      throw Exception('Failed to load risk assessment: ${response.statusCode}');
    } catch (e) {
      print('Error getting risk assessment: $e');
      rethrow;
    }
  }
  
  Future<List<dynamic>> getAlerts() async {
    try {
      print('Fetching alerts from: $baseUrl/api/alerts');
      final response = await http.get(Uri.parse('$baseUrl/api/alerts'));
      print('Alerts response status: ${response.statusCode}');
      print('Alerts response body: ${response.body}');
      
      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      throw Exception('Failed to load alerts: ${response.statusCode}');
    } catch (e) {
      print('Error getting alerts: $e');
      rethrow;
    }
  }
  
  Future<Map<String, dynamic>> getSystemStatus() async {
    try {
      print('Fetching system status from: $baseUrl/api/status');
      final response = await http.get(Uri.parse('$baseUrl/api/status'));
      print('System status response status: ${response.statusCode}');
      print('System status response body: ${response.body}');
      
      if (response.statusCode == 200) {
        return jsonDecode(response.body);
      }
      throw Exception('Failed to load system status: ${response.statusCode}');
    } catch (e) {
      print('Error getting system status: $e');
      rethrow;
    }
  }
  
  Future<void> updateNotificationSettings(Map<String, dynamic> settings) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/settings/notifications'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(settings),
      );
      if (response.statusCode != 200) {
        throw Exception('Failed to update notification settings');
      }
    } catch (e) {
      print('Error updating notification settings: $e');
      rethrow;
    }
  }
  
  Future<void> acknowledgeAlert(String alertId) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/alerts/$alertId/acknowledge'),
      );
      if (response.statusCode != 200) {
        throw Exception('Failed to acknowledge alert');
      }
    } catch (e) {
      print('Error acknowledging alert: $e');
      rethrow;
    }
  }
  
  Future<void> takeAction(String alertId, String action) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/alerts/$alertId/action'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'action': action}),
      );
      if (response.statusCode != 200) {
        throw Exception('Failed to take action');
      }
    } catch (e) {
      print('Error taking action: $e');
      rethrow;
    }
  }
  
  void dispose() {
    _channel?.sink.close();
  }
} 