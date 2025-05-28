// 📦 Package imports:
import 'package:clock/clock.dart';
import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http_mock_adapter/http_mock_adapter.dart';
// 🌎 Project imports:
import 'package:mocktail/mocktail.dart';
import 'package:oauth_interceptor/oauth_interceptor.dart';

import '../utils/custom_request_matcher.dart';
import '../utils/fake_secure_storage.dart';

class MockRequestHandler extends Mock implements RequestInterceptorHandler {}

void main() {
  group('OAuth', () {
    const tokenStorageKey = 'oauth-token';
    const refreshStorageKey = 'oauth-refresh-token';
    const expiresAtStorageKey = 'oauth-expires-at';
    const initialToken = 'abcdef';
    const nextToken = 'vwxyz';
    const initialRefreshToken = '123456';
    const nextRefreshToken = '98765';
    const expirySeconds = 36000;

    late FakeSecureStorage tokenStorage;
    late Clock clock;
    late OAuth oauth;
    late Dio dio;
    late DioAdapter adapter;

    setUp(() {
      tokenStorage = FakeSecureStorage();
      clock = Clock.fixed(DateTime(2021));
      dio = Dio();
      adapter = DioAdapter(dio: dio, matcher: const CustomRequestMatcher());
      oauth = OAuth(
        tokenUrl: 'oauth/token',
        clientId: 'id',
        clientSecret: 'secret',
        dio: dio,
        clock: clock,
        storage: tokenStorage,
      );
    });

    Future<void> saveToken(DateTime expiresAt) async {
      await tokenStorage.write(key: tokenStorageKey, value: initialToken);
      await tokenStorage.write(
        key: expiresAtStorageKey,
        value: expiresAt.millisecondsSinceEpoch.toString(),
      );
      await tokenStorage.write(
        key: refreshStorageKey,
        value: initialRefreshToken,
      );
    }

    group('Interceptor functions', () {
      test('adds user token if one is present and has not expired', () async {
        final options = RequestOptions(path: '1', headers: <String, dynamic>{});

        final expiresAt = DateTime(2021, 2);

        await saveToken(expiresAt);

        final handler = MockRequestHandler();

        await oauth.onRequest(options, handler);

        expect(
          options.headers,
          containsPair('Authorization', 'Bearer $initialToken'),
        );
        verify(() => handler.next(options)).called(1);
        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token = await oauth.token;
        expect(token, initialToken);
      });

      test('adds nothing if no token is present', () async {
        final options = RequestOptions(path: '1', headers: <String, dynamic>{});

        await tokenStorage.deleteAll();

        final handler = MockRequestHandler();

        await oauth.onRequest(options, handler);

        expect(
          options.headers,
          isNot(contains('Authorization')),
        );
        verify(() => handler.next(options)).called(1);
        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isFalse);
        final token = await oauth.token;
        expect(token, isNull);
      });

      test('adds refreshed token if refresh is successful', () async {
        final options = RequestOptions(path: '1', headers: <String, dynamic>{});
        final expiresAt = DateTime(2020, 2);
        await saveToken(expiresAt);
        adapter.onPost(
          'oauth/token',
          (server) {
            server.reply(
              200,
              <String, dynamic>{
                'access_token': nextToken,
                'expires_in': expirySeconds,
                'refresh_token': nextRefreshToken,
              },
            );
          },
          data: {
            'grant_type': 'refresh_token',
            'refresh_token': initialRefreshToken,
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        final handler = MockRequestHandler();

        await oauth.onRequest(options, handler);

        expect(
          options.headers,
          containsPair('Authorization', 'Bearer $nextToken'),
        );
        verify(() => handler.next(options)).called(1);
        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token = await oauth.token;
        expect(token, nextToken);
      });

      test('return error if token refresh returns error', () async {
        final options = RequestOptions(path: '1', headers: <String, dynamic>{});
        final expiresAt = DateTime(2020, 2);
        await saveToken(expiresAt);

        adapter.onPost(
          'oauth/token',
          (server) {
            server.reply(
              400,
              <String, dynamic>{'error_message': 'error'},
            );
          },
          data: {
            'grant_type': 'refresh_token',
            'refresh_token': initialRefreshToken,
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        final handler = MockRequestHandler();

        await expectLater(
          oauth.onRequest(options, handler),
          throwsA(isA<DioException>()),
        );
        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isFalse);
        final token = await oauth.token;
        expect(token, isNull);
      });
    });

    group('Login function', () {
      test('stores access token if login is successful', () async {
        adapter.onPost(
          'oauth/token',
          (server) {
            server.reply(
              200,
              <String, dynamic>{
                'access_token': initialToken,
                'expires_in': expirySeconds,
                'refresh_token': initialRefreshToken,
              },
            );
          },
          data: {
            'grant_type': 'password',
            'username': 'test@test.com',
            'password': 'P4ssword',
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        await oauth.login(
          PasswordGrant(username: 'test@test.com', password: 'P4ssword'),
        );

        final token = await tokenStorage.read(key: tokenStorageKey);
        final refreshToken = await tokenStorage.read(key: refreshStorageKey);
        final expiresAtMillis =
            await tokenStorage.read(key: expiresAtStorageKey);
        expect(token, initialToken);
        expect(refreshToken, initialRefreshToken);
        final expectedExpiresAt =
            DateTime(2021, 1, 1, 0, 0, expirySeconds).millisecondsSinceEpoch;
        expect(int.parse(expiresAtMillis!), expectedExpiresAt);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token2 = await oauth.token;
        expect(token2, initialToken);
      });

      test('does not store token if login request is unsuccessful', () async {
        adapter.onPost(
          'oauth/token',
          (server) {
            server.reply(
              400,
              <String, dynamic>{'error_message': 'error'},
            );
          },
          data: {
            'grant_type': 'password',
            'username': 'test@test.com',
            'password': 'P4ssword',
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        await expectLater(
          oauth.login(
            PasswordGrant(username: 'test@test.com', password: 'P4ssword'),
          ),
          throwsA(isA<DioException>()),
        );

        final hasToken = await tokenStorage.containsKey(key: tokenStorageKey);
        expect(hasToken, isFalse);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isFalse);
        final token = await oauth.token;
        expect(token, isNull);
      });
    });

    group('Client login function', () {
      test('stores access token if login is successful', () async {
        adapter.onPost(
          'oauth/token',
          (server) {
            server.reply(
              200,
              <String, dynamic>{
                'access_token': initialToken,
                'expires_in': expirySeconds,
                'refresh_token': initialRefreshToken,
              },
            );
          },
          data: {
            'grant_type': 'client_credentials',
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        await oauth.login(const ClientCredentialsGrant());

        final token = await tokenStorage.read(key: tokenStorageKey);
        final refreshToken = await tokenStorage.read(key: refreshStorageKey);
        final expiresAtMillis =
            await tokenStorage.read(key: expiresAtStorageKey);
        expect(token, initialToken);
        expect(refreshToken, initialRefreshToken);
        final expectedExpiresAt =
            DateTime(2021, 1, 1, 0, 0, expirySeconds).millisecondsSinceEpoch;
        expect(int.parse(expiresAtMillis!), expectedExpiresAt);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token2 = await oauth.token;
        expect(token2, initialToken);
      });

      test('does not store token if login request is unsuccessful', () async {
        adapter.onPost(
          'oauth/token',
          (server) {
            server.reply(
              400,
              <String, dynamic>{'error_message': 'error'},
            );
          },
          data: {
            'grant_type': 'client_credentials',
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        await expectLater(
          oauth.login(const ClientCredentialsGrant()),
          throwsA(isA<DioException>()),
        );

        final hasToken = await tokenStorage.containsKey(key: tokenStorageKey);
        expect(hasToken, isFalse);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isFalse);
        final token = await oauth.token;
        expect(token, isNull);
      });
    });
  });
}
