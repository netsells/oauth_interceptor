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
      await tokenStorage.write(key: 'oauth-token', value: 'abcdef');
      await tokenStorage.write(
        key: 'oauth-expires-at',
        value: expiresAt.millisecondsSinceEpoch.toString(),
      );
      await tokenStorage.write(key: 'oauth-refresh-token', value: '123456');
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
          containsPair('Authorization', 'Bearer abcdef'),
        );
        verify(() => handler.next(options)).called(1);
        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token = await oauth.token;
        expect(token, 'abcdef');
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
                'access_token': 'vwxyz',
                'expires_in': 36000,
                'refresh_token': '98765',
              },
            );
          },
          data: {
            'grant_type': 'refresh_token',
            'refresh_token': '123456',
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        final handler = MockRequestHandler();

        await oauth.onRequest(options, handler);

        expect(
          options.headers,
          containsPair('Authorization', 'Bearer vwxyz'),
        );
        verify(() => handler.next(options)).called(1);
        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token = await oauth.token;
        expect(token, 'vwxyz');
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
            'refresh_token': '123456',
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
                'access_token': 'abcdef',
                'expires_in': 36000,
                'refresh_token': '123456',
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

        final token = await tokenStorage.read(key: 'oauth-token');
        final refreshToken =
            await tokenStorage.read(key: 'oauth-refresh-token');
        final expiresAtMillis =
            await tokenStorage.read(key: 'oauth-expires-at');
        expect(token, 'abcdef');
        expect(refreshToken, '123456');
        final expectedExpiresAt =
            DateTime(2021, 1, 1, 0, 0, 36000).millisecondsSinceEpoch;
        expect(int.parse(expiresAtMillis!), expectedExpiresAt);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token2 = await oauth.token;
        expect(token2, 'abcdef');
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

        final hasToken = await tokenStorage.containsKey(key: 'oauth-token');
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
                'access_token': 'abcdef',
                'expires_in': 36000,
                'refresh_token': '123456',
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

        final token = await tokenStorage.read(key: 'oauth-token');
        final refreshToken =
            await tokenStorage.read(key: 'oauth-refresh-token');
        final expiresAtMillis =
            await tokenStorage.read(key: 'oauth-expires-at');
        expect(token, 'abcdef');
        expect(refreshToken, '123456');
        final expectedExpiresAt =
            DateTime(2021, 1, 1, 0, 0, 36000).millisecondsSinceEpoch;
        expect(int.parse(expiresAtMillis!), expectedExpiresAt);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token2 = await oauth.token;
        expect(token2, 'abcdef');
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

        final hasToken = await tokenStorage.containsKey(key: 'oauth-token');
        expect(hasToken, isFalse);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isFalse);
        final token = await oauth.token;
        expect(token, isNull);
      });
    });
  });
}
