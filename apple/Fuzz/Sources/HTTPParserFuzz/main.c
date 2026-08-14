extern void BondryHTTPParserFuzzHarnessAnchor(void);

__attribute__((constructor)) static void initialize_bondry_http_parser_fuzz(void) {
  BondryHTTPParserFuzzHarnessAnchor();
}
