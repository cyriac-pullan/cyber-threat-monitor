import 'package:flutter/material.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:timezone/timezone.dart' as tz;
import 'package:timezone/data/latest.dart' as tz;

class NotificationService {
  final FlutterLocalNotificationsPlugin _notifications = FlutterLocalNotificationsPlugin();
  
  Future<void> initialize() async {
    tz.initializeTimeZones();
    
    const androidSettings = AndroidInitializationSettings('@mipmap/ic_launcher');
    const iosSettings = DarwinInitializationSettings(
      requestAlertPermission: true,
      requestBadgePermission: true,
      requestSoundPermission: true,
    );
    
    const initSettings = InitializationSettings(
      android: androidSettings,
      iOS: iosSettings,
    );
    
    await _notifications.initialize(
      initSettings,
      onDidReceiveNotificationResponse: _onNotificationTap,
    );
  }
  
  Future<void> showAlertNotification({
    required String title,
    required String body,
    required String payload,
  }) async {
    const androidDetails = AndroidNotificationDetails(
      'alerts_channel',
      'Security Alerts',
      channelDescription: 'Notifications for security alerts',
      importance: Importance.high,
      priority: Priority.high,
      showWhen: true,
    );
    
    const iosDetails = DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: true,
      presentSound: true,
    );
    
    const details = NotificationDetails(
      android: androidDetails,
      iOS: iosDetails,
    );
    
    await _notifications.show(
      DateTime.now().millisecond,
      title,
      body,
      details,
      payload: payload,
    );
  }
  
  Future<void> showThreatNotification({
    required String title,
    required String body,
    required String threatLevel,
    required Map<String, dynamic> threatData,
  }) async {
    final androidDetails = AndroidNotificationDetails(
      'threats_channel',
      'Threat Notifications',
      channelDescription: 'Notifications for detected threats',
      importance: Importance.max,
      priority: Priority.high,
      showWhen: true,
      color: _getThreatColor(threatLevel),
    );
    
    final iosDetails = DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: true,
      presentSound: true,
      interruptionLevel: _getThreatInterruptionLevel(threatLevel),
    );
    
    final details = NotificationDetails(
      android: androidDetails,
      iOS: iosDetails,
    );
    
    await _notifications.show(
      DateTime.now().millisecond,
      title,
      body,
      details,
      payload: threatData.toString(),
    );
  }
  
  Future<void> showSystemNotification({
    required String title,
    required String body,
    required String type,
  }) async {
    const androidDetails = AndroidNotificationDetails(
      'system_channel',
      'System Notifications',
      channelDescription: 'Notifications for system events',
      importance: Importance.low,
      priority: Priority.low,
      showWhen: true,
    );
    
    const iosDetails = DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: true,
      presentSound: false,
    );
    
    const details = NotificationDetails(
      android: androidDetails,
      iOS: iosDetails,
    );
    
    await _notifications.show(
      DateTime.now().millisecond,
      title,
      body,
      details,
      payload: type,
    );
  }
  
  void _onNotificationTap(NotificationResponse response) {
    // Handle notification tap
    print('Notification tapped: ${response.payload}');
  }
  
  Color _getThreatColor(String threatLevel) {
    switch (threatLevel.toLowerCase()) {
      case 'high':
        return const Color(0xFFFF0000);  // Red
      case 'medium':
        return const Color(0xFFFFA500);  // Orange
      case 'low':
        return const Color(0xFFFFFF00);  // Yellow
      default:
        return const Color(0xFF0000FF);  // Blue
    }
  }
  
  InterruptionLevel _getThreatInterruptionLevel(String threatLevel) {
    switch (threatLevel.toLowerCase()) {
      case 'high':
        return InterruptionLevel.timeSensitive;
      case 'medium':
        return InterruptionLevel.active;
      case 'low':
        return InterruptionLevel.passive;
      default:
        return InterruptionLevel.passive;
    }
  }
} 