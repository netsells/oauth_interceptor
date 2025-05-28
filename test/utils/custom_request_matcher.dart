import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:http_mock_adapter/http_mock_adapter.dart';

class CustomRequestMatcher extends HttpRequestMatcher {
  const CustomRequestMatcher();

  @override
  bool matches(RequestOptions ongoingRequest, Request matcher) {
    final routeMatched =
        ongoingRequest.doesRouteMatch(ongoingRequest.path, matcher.route);
    final requestBodyMatched = ongoingRequest.method == 'GET' ||
        ongoingRequest.method == 'DELETE' ||
        ongoingRequest.matches(ongoingRequest.data, matcher.data);

    final queryParametersMatched = mapEquals<String, dynamic>(
      ongoingRequest.queryParameters,
      matcher.queryParameters,
    );

    return routeMatched &&
        ongoingRequest.method == matcher.method?.name &&
        requestBodyMatched &&
        queryParametersMatched;
  }
}
