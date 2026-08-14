use bytes::Bytes;
use http::{Response, StatusCode, header};
use serde_json::{Map, Value, json};

pub(crate) enum Message {
    Request(RpcRequest),
    Notification(RpcNotification),
    Response,
}

pub(crate) struct RpcRequest {
    pub(crate) id: Value,
    pub(crate) method: String,
    pub(crate) params: Option<Value>,
}

pub(crate) struct RpcNotification {
    pub(crate) params: Option<Value>,
}

pub(crate) struct ProtocolError {
    code: i32,
    message: &'static str,
}

pub(crate) fn parse(body: &[u8]) -> Result<Message, ProtocolError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ProtocolError {
        code: -32_700,
        message: "Parse error",
    })?;
    let object = value.as_object().ok_or(ProtocolError {
        code: -32_600,
        message: "Invalid Request",
    })?;
    if object.get("jsonrpc") != Some(&Value::String("2.0".to_owned())) {
        return Err(invalid_request());
    }
    if let Some(method) = object.get("method") {
        let method = method.as_str().ok_or_else(invalid_request)?;
        let params = object.get("params").cloned();
        return match object.get("id") {
            Some(id) if valid_id(id) => Ok(Message::Request(RpcRequest {
                id: id.clone(),
                method: method.to_owned(),
                params,
            })),
            Some(_) => Err(invalid_request()),
            None if params.as_ref().is_none_or(Value::is_object) => {
                Ok(Message::Notification(RpcNotification { params }))
            }
            None => Err(invalid_request()),
        };
    }
    if valid_response(object) {
        Ok(Message::Response)
    } else {
        Err(invalid_request())
    }
}

pub(crate) fn accepted_response() -> Response<Bytes> {
    let mut response = Response::new(Bytes::new());
    *response.status_mut() = StatusCode::ACCEPTED;
    response
}

pub(crate) fn rpc_result(id: Value, result: Value) -> Response<Bytes> {
    json_response(
        StatusCode::OK,
        json!({ "jsonrpc": "2.0", "id": id, "result": result }),
    )
}

pub(crate) fn rpc_error(
    status: StatusCode,
    id: Option<Value>,
    code: i32,
    message: &'static str,
) -> Response<Bytes> {
    rpc_error_with_data(status, id, code, message, None)
}

pub(crate) fn rpc_error_with_data(
    status: StatusCode,
    id: Option<Value>,
    code: i32,
    message: &'static str,
    data: Option<Value>,
) -> Response<Bytes> {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = data;
    }
    json_response(
        status,
        json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": error,
        }),
    )
}

pub(crate) fn error_response(status: StatusCode, error: ProtocolError) -> Response<Bytes> {
    rpc_error(status, None, error.code, error.message)
}

pub(crate) fn json_response(status: StatusCode, value: Value) -> Response<Bytes> {
    let mut response = Response::new(Bytes::from(serde_json::to_vec(&value).unwrap_or_default()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

fn valid_id(id: &Value) -> bool {
    id.is_string()
        || id
            .as_number()
            .is_some_and(|number| number.as_i64().is_some() || number.as_u64().is_some())
}

fn valid_response(response: &Map<String, Value>) -> bool {
    response.get("id").is_some_and(valid_id)
        && (response.contains_key("result") ^ response.contains_key("error"))
        && response.get("error").is_none_or(valid_error)
}

fn valid_error(error: &Value) -> bool {
    error.as_object().is_some_and(|error| {
        error.get("code").and_then(Value::as_i64).is_some()
            && error.get("message").and_then(Value::as_str).is_some()
    })
}

const fn invalid_request() -> ProtocolError {
    ProtocolError {
        code: -32_600,
        message: "Invalid Request",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Message, parse};

    #[test]
    fn distinguishes_requests_notifications_and_responses() {
        assert!(matches!(
            parse(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
            Ok(Message::Request(_))
        ));
        assert!(matches!(
            parse(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Ok(Message::Notification(_))
        ));
        assert!(matches!(
            parse(br#"{"jsonrpc":"2.0","id":"one","result":{}}"#),
            Ok(Message::Response)
        ));
    }

    #[test]
    fn rejects_batches_null_ids_and_fractional_ids() {
        for value in [
            json!([]),
            json!({ "jsonrpc": "2.0", "id": null, "method": "ping" }),
            json!({ "jsonrpc": "2.0", "id": 1.5, "method": "ping" }),
        ] {
            assert!(parse(&serde_json::to_vec(&value).unwrap_or_default()).is_err());
        }
    }
}
