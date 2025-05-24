import 'package:flutter/foundation.dart';
import '../services/threat_service.dart';
import '../services/notification_service.dart';

class ThreatProvider with ChangeNotifier {
  final ThreatService _threatService;
  final NotificationService _notificationService;
  
  List<dynamic> _alerts = [];
  Map<String, dynamic> _riskAssessment = {};
  Map<String, dynamic> _systemStatus = {};
  bool _isLoading = false;
  String? _error;
  
  ThreatProvider(this._threatService) : _notificationService = NotificationService() {
    _initialize();
  }
  
  List<dynamic> get alerts => _alerts;
  Map<String, dynamic> get riskAssessment => _riskAssessment;
  Map<String, dynamic> get systemStatus => _systemStatus;
  bool get isLoading => _isLoading;
  String? get error => _error;
  
  Future<void> _initialize() async {
    await _loadInitialData();
    await _setupWebSocket();
  }
  
  Future<void> _loadInitialData() async {
    _setLoading(true);
    try {
      await Future.wait([
        _loadAlerts(),
        _loadRiskAssessment(),
        _loadSystemStatus(),
      ]);
      _error = null;
    } catch (e) {
      _error = e.toString();
    } finally {
      _setLoading(false);
    }
  }
  
  Future<void> _setupWebSocket() async {
    await _threatService.connectWebSocket(_handleWebSocketMessage);
  }
  
  void _handleWebSocketMessage(dynamic message) {
    if (message is Map<String, dynamic>) {
      if (message['type'] == 'alert') {
        _handleNewAlert(message['data']);
      } else if (message['type'] == 'risk_update') {
        _handleRiskUpdate(message['data']);
      } else if (message['type'] == 'status_update') {
        _handleStatusUpdate(message['data']);
      }
    }
  }
  
  void _handleNewAlert(Map<String, dynamic> alert) {
    _alerts.insert(0, alert);
    notifyListeners();
    
    // Show notification
    _notificationService.showAlertNotification(
      title: 'New Security Alert',
      body: alert['message'],
      payload: alert.toString(),
    );
  }
  
  void _handleRiskUpdate(Map<String, dynamic> riskData) {
    _riskAssessment = riskData;
    notifyListeners();
    
    // Show notification for high-risk items
    if (riskData['high_risk_users']?.isNotEmpty ?? false) {
      _notificationService.showThreatNotification(
        title: 'High Risk Users Detected',
        body: '${riskData['high_risk_users'].length} users identified as high risk',
        threatLevel: 'high',
        threatData: riskData,
      );
    }
  }
  
  void _handleStatusUpdate(Map<String, dynamic> statusData) {
    _systemStatus = statusData;
    notifyListeners();
    
    // Show notification for critical status changes
    if (statusData['status'] == 'critical') {
      _notificationService.showSystemNotification(
        title: 'System Status Alert',
        body: statusData['message'],
        type: 'critical',
      );
    }
  }
  
  Future<void> _loadAlerts() async {
    _alerts = await _threatService.getAlerts();
    notifyListeners();
  }
  
  Future<void> _loadRiskAssessment() async {
    _riskAssessment = await _threatService.getRiskAssessment();
    notifyListeners();
  }
  
  Future<void> _loadSystemStatus() async {
    _systemStatus = await _threatService.getSystemStatus();
    notifyListeners();
  }
  
  void _setLoading(bool value) {
    _isLoading = value;
    notifyListeners();
  }
  
  Future<void> refresh() async {
    await _loadInitialData();
  }
  
  Future<void> acknowledgeAlert(String alertId) async {
    try {
      await _threatService.acknowledgeAlert(alertId);
      _alerts = _alerts.map((alert) {
        if (alert['id'] == alertId) {
          return {...alert, 'acknowledged': true};
        }
        return alert;
      }).toList();
      notifyListeners();
    } catch (e) {
      _error = e.toString();
      notifyListeners();
    }
  }
  
  Future<void> takeAction(String alertId, String action) async {
    try {
      await _threatService.takeAction(alertId, action);
      await refresh();
    } catch (e) {
      _error = e.toString();
      notifyListeners();
    }
  }
  
  Future<void> updateNotificationSettings(Map<String, dynamic> settings) async {
    try {
      await _threatService.updateNotificationSettings(settings);
    } catch (e) {
      _error = e.toString();
      notifyListeners();
    }
  }
  
  @override
  void dispose() {
    _threatService.dispose();
    super.dispose();
  }
} 