<!-- This file is auto-generated. Please do not modify it yourself. -->
# Protobuf Documentation
<a name="top"></a>

## Table of Contents

- [confio/ewasm/v1beta1/genesis.proto](#confio/ewasm/v1beta1/genesis.proto)
    - [GenesisState](#confio.ewasm.v1beta1.GenesisState)
    - [Params](#confio.ewasm.v1beta1.Params)
  
- [confio/ewasm/v1beta1/query.proto](#confio/ewasm/v1beta1/query.proto)
    - [Query](#confio.ewasm.v1beta1.Query)
  
- [confio/ewasm/v1beta1/tx.proto](#confio/ewasm/v1beta1/tx.proto)
    - [Msg](#confio.ewasm.v1beta1.Msg)
  
- [Scalar Value Types](#scalar-value-types)



<a name="confio/ewasm/v1beta1/genesis.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## confio/ewasm/v1beta1/genesis.proto



<a name="confio.ewasm.v1beta1.GenesisState"></a>

### GenesisState
GenesisState defines the ewasm module's genesis state.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| `params` | [Params](#confio.ewasm.v1beta1.Params) |  |  |






<a name="confio.ewasm.v1beta1.Params"></a>

### Params
Params defines the ewasm module params


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| `enable_ewasm` | [bool](#bool) |  | enable_ewasm defines a parameter to enable the ewasm module |





 <!-- end messages -->

 <!-- end enums -->

 <!-- end HasExtensions -->

 <!-- end services -->



<a name="confio/ewasm/v1beta1/query.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## confio/ewasm/v1beta1/query.proto


 <!-- end messages -->

 <!-- end enums -->

 <!-- end HasExtensions -->


<a name="confio.ewasm.v1beta1.Query"></a>

### Query
Query defines the gRPC querier service.

| Method Name | Request Type | Response Type | Description | HTTP Verb | Endpoint |
| ----------- | ------------ | ------------- | ------------| ------- | -------- |

 <!-- end services -->



<a name="confio/ewasm/v1beta1/tx.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## confio/ewasm/v1beta1/tx.proto


 <!-- end messages -->

 <!-- end enums -->

 <!-- end HasExtensions -->


<a name="confio.ewasm.v1beta1.Msg"></a>

### Msg
Msg defines the ewasm Msg service.

| Method Name | Request Type | Response Type | Description | HTTP Verb | Endpoint |
| ----------- | ------------ | ------------- | ------------| ------- | -------- |

 <!-- end services -->



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

