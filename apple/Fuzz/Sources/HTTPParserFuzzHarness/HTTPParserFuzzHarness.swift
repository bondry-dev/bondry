@_spi(BondryFuzzing) import BondryApple
import Foundation

@_cdecl("LLVMFuzzerTestOneInput")
public func llvmFuzzerTestOneInput(
  _ bytes: UnsafePointer<UInt8>?,
  _ count: Int
) -> Int32 {
  guard let bytes else {
    fuzzBoundedHTTP1ResponseParser(Data())
    return 0
  }
  fuzzBoundedHTTP1ResponseParser(Data(bytes: bytes, count: count))
  return 0
}

@_cdecl("BondryHTTPParserFuzzHarnessAnchor")
public func bondryHTTPParserFuzzHarnessAnchor() {}
