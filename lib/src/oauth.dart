import 'package:clock/clock.dart';
import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:oauth_interceptor/src/oauth_grant_type.dart';
import 'package:time/time.dart';

class OAuth extends Interceptor {
  OAuth({
    required this.tokenUrl,
    required this.clientId,
    required this.clientSecret,
    this.dio,
    this.name = 'oauth',
    this.clock = const Clock(),
    this.storage = const FlutterSecureStorage(),
  });

  final String tokenUrl;
  final String clientId;
  final String clientSecret;
  final String name;
  final Dio? dio;
  final Clock clock;
  final FlutterSecureStorage storage;

  Future<bool> get isSignedIn async {
    final token = await storage.read(key: '$name-token');
    return token != null;
  }

  @override
  Future<void> onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    final expiresAtMillis = await storage.read(key: '$name-expiresAt');
    if (expiresAtMillis != null) {
      final expiresAt = DateTime.fromMillisecondsSinceEpoch(
        int.parse(expiresAtMillis),
      );

      if (expiresAt.isBefore(clock.now())) {
        await refresh();
      }
    }

    final token = await storage.read(key: '$name-token');

    if (token != null) {
      options.headers['Authorization'] = 'Bearer $token';
    }
    return super.onRequest(options, handler);
  }

  Future<void> login(OAuthGrantType grant) async {
    await logout();

    final dio = this.dio ?? Dio();
    final options = grant.handle(
      RequestOptions(
        path: tokenUrl,
        method: 'POST',
        contentType: 'application/x-www-form-urlencoded',
        responseType: ResponseType.json,
      ),
    );

    (options.data as Map<String, String>).addAll({
      'client_id': clientId,
      'client_secret': clientSecret,
    });

    final response = await dio.request<Map<String, dynamic>>(
      tokenUrl,
      data: options.data,
      options: Options(
        contentType: options.contentType,
        headers: options.headers,
        method: options.method,
      ),
    );
    final body = response.data!;
    await storage.write(
      key: '$name-token',
      value: body['access_token'] as String?,
    );
    await storage.write(
      key: '$name-refresh-token',
      value: body['refresh_token'] as String?,
    );
    final expiresIn = body['expires_in'] as int;
    final expiresAt = clock.now().add(expiresIn.seconds).millisecondsSinceEpoch;
    await storage.write(
      key: '$name-expires-at',
      value: expiresAt.toString(),
    );
  }

  Future<void> refresh() async {
    final refreshToken = await storage.read(key: '$name-refresh-token');
    if (refreshToken != null) {
      final grant = RefreshTokenGrant(
        refreshToken: refreshToken,
      );
      await login(grant);
    }
  }

  Future<void> logout() async {
    await storage.delete(key: '$name-token');
    await storage.delete(key: '$name-refresh-token');
    await storage.delete(key: '$name-expires-at');
  }
}
